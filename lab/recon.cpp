/*
 * recon.dll  v10  — full self-discovering IL2CPP lane resolver
 *
 * Changes from v9:
 *   - ELF scan start lowered to 0x10000000 (physical pages can land anywhere)
 *   - Removed e_shnum >= 10 filter — Android strips section headers (e_shnum=0)
 *   - ELF confirmation switched to PT_DYNAMIC walk (phdrs always present)
 *   - Stage 4 dynsym lookup now uses PT_DYNAMIC → DT_SYMTAB/DT_STRTAB/DT_HASH
 *     instead of section headers
 *   - Added DIRECT_LANE_GPA compile-time bypass for bot loop testing
 *   - Added HVA→GPA helper log line so CE HVAs can be converted manually
 *   - InitRangeMap logs HCPtrStart so user can compute: GPA = CE_HVA - HCPtrStart
 *   - ELF scan logs every ARM64 ET_DYN hit (even rejected ones) for diagnosis
 *
 * DIRECT_LANE_GPA mode:
 *   Run recon once to get the current HCPtrStart printed in Stage 2.
 *   Then compute: GPA = CE_HVA - HCPtrStart
 *   Set DIRECT_LANE_GPA to that GPA value and recompile.
 *   The DLL will skip stages 3-6 and go straight to the bot loop.
 *   Set to 0 to re-enable full self-discovery.
 *
 * Compile (VS x64 Native Tools prompt):
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>

// ── compile-time bypass ───────────────────────────────────────────────────────
// Set to the GPA of the lane field (computed from CE HVA - HCPtrStart).
// Set to 0 to run full self-discovery.
#define DIRECT_LANE_GPA  0x0000000000000000ULL

// ── types ─────────────────────────────────────────────────────────────────────

typedef void*     PUVM;
typedef void*     PVM;
typedef uint64_t  RTGCPHYS;

typedef void*    (WINAPI* pfnVMR3GetUVM)               (PVM);
typedef void*    (WINAPI* pfnVMR3GetVM)                (PUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PVM);
typedef int      (WINAPI* pfnPGMPhysSimpleReadGCPhys)  (PVM, void*, RTGCPHYS, size_t);
typedef int      (WINAPI* pfnPGMPhysSimpleWriteGCPhys) (PVM, RTGCPHYS, const void*, size_t);

// ── globals ───────────────────────────────────────────────────────────────────

static const uint32_t UVM_MAGIC         = 0x19700823;
static const uint32_t PGM_RANGES_OFFSET = 0x1010;
static const uint64_t GUEST_RAM_BYTES   = 0xE0000000ULL; // 3584 MB

#define LOG_PATH "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;
static pfnPGMPhysSimpleReadGCPhys   g_fnRead;
static pfnPGMPhysSimpleWriteGCPhys  g_fnWrite;

static FILE*    g_log    = nullptr;
static void*    g_pVM    = nullptr;
static PUVM     g_pUVM   = nullptr;
static uint64_t g_hvaBase = 0;   // HCPtrStart of the flat guest RAM range
static uint64_t g_gpaBase = 0;   // GCPhys start (should be 0)

// ── logging ───────────────────────────────────────────────────────────────────

#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    char _b[512]; \
    snprintf(_b, sizeof(_b), "[recon] " fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(_b); \
} while(0)

// ── safe guest RAM read ───────────────────────────────────────────────────────

static bool GuestRead(RTGCPHYS gpa, void* dst, size_t cb)
{
    if (gpa + cb > GUEST_RAM_BYTES) return false;
    int rc = -1;
    __try { rc = g_fnRead(g_pVM, dst, gpa, cb); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
    return rc == 0; // VINF_SUCCESS
}

static bool GuestRead64(RTGCPHYS gpa, uint64_t* out) { return GuestRead(gpa, out, 8); }
static bool GuestRead32(RTGCPHYS gpa, uint32_t* out) { return GuestRead(gpa, out, 4); }

static std::string GuestReadStr(RTGCPHYS gpa, size_t max_len = 256)
{
    std::string s;
    s.reserve(64);
    for (size_t i = 0; i < max_len; i++) {
        uint8_t c = 0;
        if (!GuestRead(gpa + i, &c, 1)) break;
        if (c == 0) break;
        s += (char)c;
    }
    return s;
}

// ── host virtual ↔ GPA (flat single range) ───────────────────────────────────

static bool GpaFromHva(uint64_t hva, RTGCPHYS* gpa)
{
    if (g_hvaBase == 0) return false;
    if (hva < g_hvaBase || hva >= g_hvaBase + GUEST_RAM_BYTES) return false;
    *gpa = g_gpaBase + (hva - g_hvaBase);
    return true;
}

// ── prefault host memory ──────────────────────────────────────────────────────

static void Prefault(void* base, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)base;
    size_t pages = (size + 0xFFF) / 0x1000;
    for (size_t i = 0; i < pages; i++)
        __try { (void)p[i * 0x1000]; } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 1 — VBox bridge
// ═══════════════════════════════════════════════════════════════════════════════

static bool InitVBoxBridge()
{
    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("BstkVMM.dll not found"); return false; }

#define RESOLVE(name, type, var) \
    var = (type)GetProcAddress(hVMM, #name); \
    if (!var) { LOG("missing export " #name); return false; } \
    LOG(#name " = %p", (void*)var);

    RESOLVE(VMR3GetUVM,                pfnVMR3GetUVM,                g_fnGetUVM)
    RESOLVE(VMR3GetVM,                 pfnVMR3GetVM,                 g_fnGetVM)
    RESOLVE(PGMR3PhysGetRamRangeCount, pfnPGMR3PhysGetRamRangeCount, g_fnRangeCount)
    RESOLVE(PGMPhysSimpleReadGCPhys,   pfnPGMPhysSimpleReadGCPhys,   g_fnRead)
    RESOLVE(PGMPhysSimpleWriteGCPhys,  pfnPGMPhysSimpleWriteGCPhys,  g_fnWrite)
#undef RESOLVE
    return true;
}

static bool ScanForUVM()
{
    SYSTEM_INFO si = {}; GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }
        size_t rSize = mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & 0xFF) != PAGE_NOACCESS &&
            (mbi.Protect & 0xFF) != PAGE_EXECUTE  &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.Type != MEM_IMAGE && rSize >= 4)
        {
            uintptr_t rBase = (uintptr_t)mbi.BaseAddress;
            uintptr_t rEnd  = rBase + rSize;
            uintptr_t pg    = (rBase + 0xFFF) & ~(uintptr_t)0xFFF;

            while (pg + 4 <= rEnd) {
                __try {
                    if (*(uint32_t*)pg == UVM_MAGIC) {
                        void* pvm = nullptr;
                        __try { pvm = *(void**)(pg + 8); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (!pvm) { pg += 0x1000; continue; }

                        void* gotPVM = nullptr; PUVM gotUVM = nullptr;
                        __try { gotPVM = g_fnGetVM((PUVM)pg); }   __except(EXCEPTION_EXECUTE_HANDLER) {}
                        __try { gotUVM = g_fnGetUVM(pvm); }        __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (gotPVM != pvm || gotUVM != (PUVM)pg) { pg += 0x1000; continue; }

                        Prefault(pvm, 0x2000);
                        uint32_t rc = 0;
                        __try { rc = g_fnRangeCount((PVM)pvm); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (rc >= 1 && rc <= 128) {
                            g_pUVM = (PUVM)pg;
                            g_pVM  = pvm;
                            LOG("pUVM=%p  pVM=%p  nRanges=%u", (void*)pg, pvm, rc);
                            return true;
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
                pg += 0x1000;
            }
        }
        addr += rSize;
    }
    LOG("UVM scan failed");
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 2 — Map the flat guest RAM range
// ═══════════════════════════════════════════════════════════════════════════════

static bool InitRangeMap()
{
    uintptr_t headPtr = 0;
    __try { headPtr = *(uintptr_t*)((uintptr_t)g_pVM + PGM_RANGES_OFFSET); }
    __except(EXCEPTION_EXECUTE_HANDLER) { LOG("pVM+0x1010 read threw"); return false; }

    if (!headPtr) { LOG("pRamRangesXR3 is null"); return false; }
    LOG("pRamRangesXR3 = %p", (void*)headPtr);

    Prefault((void*)headPtr, 0x200);
    uint32_t nextOff = 0;
    for (uint32_t off = 0x20; off <= 0x100; off += 8) {
        uintptr_t candidate = 0;
        __try { candidate = *(uintptr_t*)(headPtr + off); }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (candidate == 0) { if (!nextOff) nextOff = off; break; }
        if ((candidate >> 48) != 0 && (candidate >> 48) != 0xFFFF) continue;
        uint64_t t0 = 0;
        __try { t0 = *(uint64_t*)candidate; } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (t0 == 0 || (t0 < 0x100000000ULL && (t0 & 0xFFF) == 0)) {
            if (!nextOff) nextOff = off;
            break;
        }
    }
    if (!nextOff) nextOff = 0x38;
    LOG("pNextR3 offset = +0x%02X", nextOff);

    uintptr_t node = headPtr;
    for (int idx = 0; node && idx < 64; idx++) {
        Prefault((void*)node, 0x200);
        uint64_t gcStart = 0, gcEnd = 0, hcPtr = 0;
        __try {
            gcStart = *(uint64_t*)(node + 0x00);
            gcEnd   = *(uint64_t*)(node + 0x08);
            hcPtr   = *(uint64_t*)(node + 0x10);
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }

        uint64_t sz = (gcEnd >= gcStart) ? (gcEnd - gcStart + 1) : 0;
        LOG("range[%d]  GC:%016llX-%016llX  HC:%016llX  %8.2f MB",
            idx, (unsigned long long)gcStart, (unsigned long long)gcEnd,
            (unsigned long long)hcPtr, sz / (1024.0 * 1024.0));

        if (gcStart == 0 && sz >= 0x10000000ULL) {
            g_hvaBase = hcPtr;
            g_gpaBase = gcStart;
            LOG("guest RAM base: HVA=%016llX  GPA=%016llX  size=%.2f GB",
                (unsigned long long)hcPtr,
                (unsigned long long)gcStart,
                sz / (1024.0 * 1024.0 * 1024.0));
            // ── CE helper ──────────────────────────────────────────────────
            // If you found the lane address in Cheat Engine (attached to HD-Player.exe),
            // compute the GPA like this:
            //   GPA = CE_HVA - HCPtrStart
            // where HCPtrStart is the HC value printed above.
            // Then set DIRECT_LANE_GPA at the top of this file and recompile.
            LOG("CE->GPA formula: GPA = CE_HVA - %016llX", (unsigned long long)hcPtr);
        }

        uintptr_t next = 0;
        __try { next = *(uintptr_t*)(node + nextOff); } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
        node = next;
    }

    if (!g_hvaBase) { LOG("failed to find main guest RAM range"); return false; }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 3 — Find libil2cpp.so ELF base in guest RAM
// ═══════════════════════════════════════════════════════════════════════════════
//
// Key fixes vs v9:
//   1. Scan from 0x10000000 (not 0x60000000) — physical pages can be anywhere
//   2. No e_shnum filter — Android strips section headers, e_shnum is often 0
//   3. Confirmation via PT_DYNAMIC (always present) instead of .dynsym section
//   4. Log every ARM64 ET_DYN hit even if confirmation fails

// ELF64 structs (little-endian ARM64)
struct Elf64Hdr {
    uint8_t  e_ident[16];
    uint16_t e_type;        // ET_DYN = 3
    uint16_t e_machine;     // EM_AARCH64 = 183
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

// Elf64_Phdr — 56 bytes
struct Elf64Phdr {
    uint32_t p_type;    // PT_LOAD=1, PT_DYNAMIC=2, PT_INTERP=3
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

// Elf64_Dyn — 16 bytes
struct Elf64Dyn {
    int64_t  d_tag;
    uint64_t d_val;
};

// Elf64_Sym — 24 bytes
struct Elf64Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

// Elf64_Shdr (still used in stage 4 for the rare non-stripped build)
struct Elf64Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

static const uint8_t ELF_MAGIC[4] = { 0x7f, 'E', 'L', 'F' };

// DT_ tags we care about
#define DT_NULL     0
#define DT_NEEDED   1
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_SONAME   14
#define DT_GNU_HASH 0x6ffffef5

// Convert a runtime VAddr from PT_DYNAMIC to a GPA.
// Android loads PIE SOs with the ELF's vaddr base = 0, so runtime_va = ELF file offset
// (the LOAD segments map p_vaddr 0x0 ... N at file offset p_offset).
// We find the LOAD segment that covers this vaddr and compute the GPA.
static bool VaddrToGpa(RTGCPHYS elfBase, const Elf64Hdr& hdr,
                       uint64_t vaddr, RTGCPHYS* out_gpa)
{
    for (uint16_t pi = 0; pi < hdr.e_phnum; pi++) {
        Elf64Phdr ph;
        RTGCPHYS ph_gpa = elfBase + hdr.e_phoff + (uint64_t)pi * sizeof(Elf64Phdr);
        if (!GuestRead(ph_gpa, &ph, sizeof(ph))) continue;
        if (ph.p_type != 1) continue; // PT_LOAD
        if (vaddr < ph.p_vaddr || vaddr >= ph.p_vaddr + ph.p_filesz) continue;
        *out_gpa = elfBase + ph.p_offset + (vaddr - ph.p_vaddr);
        return true;
    }
    return false;
}

static RTGCPHYS FindLibIl2CppBase()
{
    LOG("scanning guest RAM for libil2cpp.so ELF header ...");
    LOG("scan range: GPA 0x10000000 - 0x%08llX (step 4KB)", (unsigned long long)GUEST_RAM_BYTES);

    uint8_t page[16];
    uint32_t candidates = 0;

    // Start at 0x10000000 — skip the first 256 MB (kernel/firmware pages)
    for (RTGCPHYS gpa = 0x10000000ULL; gpa < GUEST_RAM_BYTES; gpa += 0x1000) {

        // Log progress every 256 MB
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  ELF scan progress: GPA=%016llX", (unsigned long long)gpa);

        if (!GuestRead(gpa, page, 16)) continue;
        if (memcmp(page, ELF_MAGIC, 4) != 0) continue;
        if (page[4] != 2) continue; // EI_CLASS = ELFCLASS64
        if (page[5] != 1) continue; // EI_DATA  = ELFDATA2LSB

        Elf64Hdr hdr;
        if (!GuestRead(gpa, &hdr, sizeof(hdr))) continue;
        if (hdr.e_type    != 3)   continue; // ET_DYN
        if (hdr.e_machine != 183) continue; // EM_AARCH64

        // e_phnum sanity (phdrs always present on Android)
        if (hdr.e_phnum == 0 || hdr.e_phnum > 128) continue;
        if (hdr.e_phoff  == 0) continue;
        if (hdr.e_phentsize != sizeof(Elf64Phdr)) {
            // Some older toolchains use 56 exactly; we already match that.
            // If it's something else, skip.
            continue;
        }

        // NOTE: e_shnum is intentionally NOT checked here.
        // Android stripped SOs have e_shnum=0, e_shoff=0.

        candidates++;

        // Look for PT_DYNAMIC program header
        bool has_dynamic = false;
        uint64_t dyn_offset = 0, dyn_size = 0;
        uint64_t load_vaddr = UINT64_MAX; // lowest PT_LOAD p_vaddr (should be 0 for PIE)

        for (uint16_t pi = 0; pi < hdr.e_phnum; pi++) {
            Elf64Phdr ph;
            RTGCPHYS ph_gpa = gpa + hdr.e_phoff + (uint64_t)pi * sizeof(Elf64Phdr);
            if (!GuestRead(ph_gpa, &ph, sizeof(ph))) continue;

            if (ph.p_type == 1 && ph.p_vaddr < load_vaddr) // PT_LOAD
                load_vaddr = ph.p_vaddr;

            if (ph.p_type == 2) { // PT_DYNAMIC
                has_dynamic = true;
                dyn_offset  = ph.p_offset;
                dyn_size    = ph.p_filesz;
            }
        }

        if (!has_dynamic) {
            LOG("  ARM64 ET_DYN @ GPA=%016llX — no PT_DYNAMIC, skipping",
                (unsigned long long)gpa);
            continue;
        }

        LOG("  ARM64 ET_DYN @ GPA=%016llX  phnum=%u  PT_DYNAMIC off=0x%llX sz=0x%llX",
            (unsigned long long)gpa, hdr.e_phnum,
            (unsigned long long)dyn_offset, (unsigned long long)dyn_size);

        // Parse PT_DYNAMIC to find DT_STRTAB + DT_SYMTAB + DT_STRSZ + DT_SYMENT
        // Also look for DT_SONAME to confirm "libil2cpp.so"
        uint64_t dt_strtab  = 0, dt_symtab = 0, dt_strsz = 0, dt_syment = 0;
        uint64_t dt_hash    = 0, dt_gnu_hash = 0, dt_soname_off = 0;
        bool has_soname = false;

        uint64_t n_dyn = dyn_size / sizeof(Elf64Dyn);
        if (n_dyn > 256) n_dyn = 256; // sanity

        for (uint64_t di = 0; di < n_dyn; di++) {
            Elf64Dyn d;
            RTGCPHYS d_gpa = gpa + dyn_offset + di * sizeof(Elf64Dyn);
            if (!GuestRead(d_gpa, &d, sizeof(d))) break;
            if (d.d_tag == DT_NULL) break;

            switch (d.d_tag) {
                case DT_STRTAB:   dt_strtab       = d.d_val; break;
                case DT_SYMTAB:   dt_symtab        = d.d_val; break;
                case DT_STRSZ:    dt_strsz         = d.d_val; break;
                case DT_SYMENT:   dt_syment         = d.d_val; break;
                case DT_HASH:     dt_hash           = d.d_val; break;
                case DT_GNU_HASH: dt_gnu_hash       = d.d_val; break;
                case DT_SONAME:   dt_soname_off = d.d_val; has_soname = true; break;
            }
        }

        if (!dt_strtab || !dt_symtab) {
            LOG("    missing DT_STRTAB or DT_SYMTAB, skipping");
            continue;
        }

        // DT_STRTAB / DT_SYMTAB are virtual addresses.
        // For a PIE SO with load_vaddr=0 they equal file offsets.
        // Convert to GPA via LOAD segment mapping.
        RTGCPHYS strtab_gpa = 0, symtab_gpa = 0;
        if (!VaddrToGpa(gpa, hdr, dt_strtab, &strtab_gpa)) {
            // Fallback for PIE with vbase=0
            strtab_gpa = gpa + dt_strtab;
        }
        if (!VaddrToGpa(gpa, hdr, dt_symtab, &symtab_gpa)) {
            symtab_gpa = gpa + dt_symtab;
        }

        // Check DT_SONAME if present
        if (has_soname && dt_strsz > 0) {
            std::string soname = GuestReadStr(strtab_gpa + dt_soname_off, 64);
            LOG("    SONAME = \"%s\"", soname.c_str());
            if (soname == "libil2cpp.so") {
                LOG("CONFIRMED libil2cpp.so via SONAME @ GPA=%016llX",
                    (unsigned long long)gpa);
                return gpa;
            }
            // Not libil2cpp.so — but fall through to symbol check anyway
            // in case SONAME is absent or mismatched
        }

        // Symbol-name confirmation: scan dynsym for "il2cpp_domain_get"
        // We need the symbol count. Try DT_HASH first ([1] = nchain = nsyms),
        // then DT_GNU_HASH, then fall back to scanning until st_name OOB.
        uint64_t nsyms = 0;
        if (dt_hash) {
            RTGCPHYS hash_gpa = 0;
            if (!VaddrToGpa(gpa, hdr, dt_hash, &hash_gpa))
                hash_gpa = gpa + dt_hash;
            uint32_t nchain = 0;
            if (GuestRead32(hash_gpa + 4, &nchain) && nchain > 0 && nchain < 500000)
                nsyms = nchain;
        }
        if (!nsyms && dt_gnu_hash) {
            // GNU hash: [0]=nbuckets [1]=symoffset — symbols start at symoffset
            // We can't get exact count cheaply; cap at a safe maximum
            nsyms = 200000;
        }
        if (!nsyms) nsyms = 200000; // scan-until-OOB fallback

        uint32_t sym_size = (dt_syment > 0 && dt_syment <= 64)
                            ? (uint32_t)dt_syment
                            : (uint32_t)sizeof(Elf64Sym);

        bool confirmed = false;
        for (uint64_t si = 0; si < nsyms; si++) {
            Elf64Sym sym;
            RTGCPHYS sym_gpa = symtab_gpa + si * sym_size;
            if (!GuestRead(sym_gpa, &sym, sizeof(sym))) break;

            // Bounds-check st_name against strtab
            if (dt_strsz && sym.st_name >= dt_strsz) break;

            std::string name = GuestReadStr(strtab_gpa + sym.st_name, 32);
            if (name == "il2cpp_domain_get") {
                LOG("CONFIRMED libil2cpp.so @ GPA=%016llX  il2cpp_domain_get RVA=0x%llX",
                    (unsigned long long)gpa, (unsigned long long)sym.st_value);
                confirmed = true;
                break;
            }
        }

        if (confirmed) return gpa;

        LOG("    ARM64 ET_DYN @ %016llX not confirmed as libil2cpp.so",
            (unsigned long long)gpa);
    }

    LOG("libil2cpp.so not found in guest RAM (checked %u ARM64 ET_DYN candidates)",
        candidates);
    return (RTGCPHYS)-1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 4 — Read IL2CPP export RVAs
// ═══════════════════════════════════════════════════════════════════════════════
//
// Uses PT_DYNAMIC (DT_SYMTAB / DT_STRTAB / DT_HASH) rather than section headers.
// Falls back to section header walk if the SO happens to be unstripped.

struct Il2CppExports {
    uint64_t domain_get;
    uint64_t domain_get_assemblies;
    uint64_t class_from_name;
    uint64_t class_get_field_from_name;
    uint64_t class_get_fields;
    uint64_t class_num_fields;
    uint64_t field_get_offset;
    uint64_t field_get_name;
    uint64_t assembly_get_image;
    uint64_t image_get_class;
    uint64_t image_get_class_count;
    bool ok;
};

static Il2CppExports ReadIl2CppExports(RTGCPHYS elfBase)
{
    Il2CppExports exp = {};
    Elf64Hdr hdr;
    if (!GuestRead(elfBase, &hdr, sizeof(hdr))) return exp;

    // Parse PT_DYNAMIC
    uint64_t dt_strtab = 0, dt_symtab = 0, dt_strsz = 0, dt_syment = 0, dt_hash = 0;
    for (uint16_t pi = 0; pi < hdr.e_phnum; pi++) {
        Elf64Phdr ph;
        if (!GuestRead(elfBase + hdr.e_phoff + (uint64_t)pi * sizeof(Elf64Phdr), &ph, sizeof(ph))) continue;
        if (ph.p_type != 2) continue; // PT_DYNAMIC

        uint64_t n_dyn = ph.p_filesz / sizeof(Elf64Dyn);
        if (n_dyn > 256) n_dyn = 256;
        for (uint64_t di = 0; di < n_dyn; di++) {
            Elf64Dyn d;
            if (!GuestRead(elfBase + ph.p_offset + di * sizeof(Elf64Dyn), &d, sizeof(d))) break;
            if (d.d_tag == DT_NULL) break;
            switch (d.d_tag) {
                case DT_STRTAB: dt_strtab  = d.d_val; break;
                case DT_SYMTAB: dt_symtab  = d.d_val; break;
                case DT_STRSZ:  dt_strsz   = d.d_val; break;
                case DT_SYMENT: dt_syment  = d.d_val; break;
                case DT_HASH:   dt_hash    = d.d_val; break;
            }
        }
        break;
    }

    if (!dt_strtab || !dt_symtab) {
        LOG("ReadIl2CppExports: PT_DYNAMIC missing strtab/symtab"); return exp;
    }

    RTGCPHYS strtab_gpa = 0, symtab_gpa = 0;
    if (!VaddrToGpa(elfBase, hdr, dt_strtab, &strtab_gpa)) strtab_gpa = elfBase + dt_strtab;
    if (!VaddrToGpa(elfBase, hdr, dt_symtab, &symtab_gpa)) symtab_gpa = elfBase + dt_symtab;

    uint64_t nsyms = 0;
    if (dt_hash) {
        RTGCPHYS hash_gpa = 0;
        if (!VaddrToGpa(elfBase, hdr, dt_hash, &hash_gpa)) hash_gpa = elfBase + dt_hash;
        uint32_t nchain = 0;
        if (GuestRead32(hash_gpa + 4, &nchain) && nchain < 500000) nsyms = nchain;
    }
    if (!nsyms) nsyms = 200000;

    uint32_t sym_size = (dt_syment > 0 && dt_syment <= 64)
                        ? (uint32_t)dt_syment
                        : (uint32_t)sizeof(Elf64Sym);

    for (uint64_t si = 0; si < nsyms; si++) {
        Elf64Sym sym;
        RTGCPHYS sym_gpa = symtab_gpa + si * sym_size;
        if (!GuestRead(sym_gpa, &sym, sizeof(sym))) break;
        if (dt_strsz && sym.st_name >= dt_strsz) break;
        if (sym.st_value == 0) continue;

        std::string name = GuestReadStr(strtab_gpa + sym.st_name, 64);

        if      (name == "il2cpp_domain_get")                 exp.domain_get                 = sym.st_value;
        else if (name == "il2cpp_domain_get_assemblies")      exp.domain_get_assemblies       = sym.st_value;
        else if (name == "il2cpp_class_from_name")            exp.class_from_name             = sym.st_value;
        else if (name == "il2cpp_class_get_field_from_name")  exp.class_get_field_from_name   = sym.st_value;
        else if (name == "il2cpp_class_get_fields")           exp.class_get_fields            = sym.st_value;
        else if (name == "il2cpp_class_num_fields")           exp.class_num_fields            = sym.st_value;
        else if (name == "il2cpp_field_get_offset")           exp.field_get_offset            = sym.st_value;
        else if (name == "il2cpp_field_get_name")             exp.field_get_name              = sym.st_value;
        else if (name == "il2cpp_assembly_get_image")         exp.assembly_get_image          = sym.st_value;
        else if (name == "il2cpp_image_get_class")            exp.image_get_class             = sym.st_value;
        else if (name == "il2cpp_image_get_class_count")      exp.image_get_class_count       = sym.st_value;
    }

    exp.ok = exp.domain_get && exp.field_get_offset && exp.field_get_name;
    if (exp.ok)
        LOG("exports: domain_get=RVA+%llX  field_get_offset=RVA+%llX",
            (unsigned long long)exp.domain_get,
            (unsigned long long)exp.field_get_offset);
    else
        LOG("WARNING: exports incomplete (domain_get=%llu field_get_offset=%llu)",
            (unsigned long long)exp.domain_get,
            (unsigned long long)exp.field_get_offset);
    return exp;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 5 — Walk IL2CPP object graph to find field byte offsets
// ═══════════════════════════════════════════════════════════════════════════════
//
// Il2CppClass layout (ARM64, metadata v31, Unity ~2021):
//   +0x10  char*             name
//   +0x18  char*             namespaze
//   +0x80  Il2CppFieldInfo*  fields
//   +0xBC  uint16_t          field_count  (probe 0xBC/0xB8/0xC0/0xC4)
//
// Il2CppFieldInfo (ARM64):
//   +0x00  char*     name
//   +0x08  Il2CppType* type
//   +0x10  uint32_t  offset  (byte offset within instance; 0xFFFFFFFF = static)
//   +0x14  uint32_t  token

struct FieldResult {
    uint32_t currentLane_offset;
    uint32_t laneIndex_offset;
    uint64_t class_gpa;
    bool ok;
};

static const uint32_t CLASS_OFF_NAME       = 0x10;
static const uint32_t CLASS_OFF_NAMESPACE  = 0x18;
static const uint32_t CLASS_OFF_FIELDS     = 0x80;
static const uint32_t FIELD_SIZE           = 0x18; // sizeof(Il2CppFieldInfo) on ARM64
static const uint32_t FIELD_OFF_NAME       = 0x00;
static const uint32_t FIELD_OFF_OFFSET     = 0x10;

static bool TryReadFieldOffset(RTGCPHYS fields_gpa, uint32_t field_idx,
                                const char* expected_name, uint32_t* out_offset)
{
    RTGCPHYS fgpa = fields_gpa + (uint64_t)field_idx * FIELD_SIZE;
    uint64_t name_ptr = 0;
    if (!GuestRead64(fgpa + FIELD_OFF_NAME, &name_ptr)) return false;
    if (name_ptr == 0 || name_ptr >= GUEST_RAM_BYTES) return false;

    std::string fname = GuestReadStr(name_ptr, 64);
    if (fname != expected_name) return false;

    uint32_t byte_off = 0;
    if (!GuestRead32(fgpa + FIELD_OFF_OFFSET, &byte_off)) return false;
    if (byte_off == 0xFFFFFFFF || byte_off > 0x10000) return false;

    *out_offset = byte_off;
    return true;
}

// Try multiple known field_count offsets for a class (layout varies by Unity version)
static bool ReadClassFieldCount(RTGCPHYS class_gpa, uint32_t* out_count)
{
    static const uint32_t offsets[] = { 0xBC, 0xB8, 0xC0, 0xC4, 0x88, 0x90 };
    for (auto off : offsets) {
        uint32_t v = 0;
        if (!GuestRead32(class_gpa + off, &v)) continue;
        uint16_t fc = (uint16_t)(v & 0xFFFF);
        if (fc == 99) { *out_count = fc; return true; }
    }
    return false;
}

static FieldResult FindLaneFields(RTGCPHYS elfBase, const Il2CppExports& /*exp*/)
{
    FieldResult res = {};

    // Try domain walk first
    LOG("scanning for Il2CppDomain ...");
    RTGCPHYS domain_gpa = 0;

    for (RTGCPHYS off = 0x2000000; off < 0x5000000 && !domain_gpa; off += 8) {
        RTGCPHYS scan_gpa = elfBase + off;
        if (scan_gpa + 8 > GUEST_RAM_BYTES) break;

        uint64_t ptr = 0;
        if (!GuestRead64(scan_gpa, &ptr)) continue;
        if (ptr == 0 || ptr >= GUEST_RAM_BYTES || (ptr & 7)) continue;

        uint64_t name_ptr = 0;
        if (!GuestRead64(ptr, &name_ptr)) continue;
        if (name_ptr == 0 || name_ptr >= GUEST_RAM_BYTES) continue;

        uint8_t str_start[8] = {};
        if (!GuestRead(name_ptr, str_start, 7)) continue;
        if (memcmp(str_start, "IL2CPP", 6) != 0) continue;

        uint64_t asm_list = 0;
        if (!GuestRead64(ptr + 0x10, &asm_list)) continue;
        if (asm_list == 0 || asm_list >= GUEST_RAM_BYTES || (asm_list & 7)) continue;

        std::string domain_name = GuestReadStr(name_ptr, 64);
        LOG("Il2CppDomain candidate @ GPA=%016llX  name=\"%s\"",
            (unsigned long long)ptr, domain_name.c_str());
        domain_gpa = ptr;
    }

    if (!domain_gpa)
        LOG("Il2CppDomain not found — falling back to brute-force class scan");

    if (domain_gpa) {
        uint64_t asm_list = 0, asm_count = 0;
        GuestRead64(domain_gpa + 0x10, &asm_list);
        GuestRead64(domain_gpa + 0x18, &asm_count);
        if (asm_count == 0 || asm_count > 1024) {
            LOG("assembly count %llu implausible, trying +0x20",
                (unsigned long long)asm_count);
            GuestRead64(domain_gpa + 0x20, &asm_count);
        }
        LOG("assembly list @ GPA=%016llX  count=%llu",
            (unsigned long long)asm_list, (unsigned long long)asm_count);

        for (uint64_t ai = 0; ai < asm_count && ai < 512; ai++) {
            uint64_t asm_ptr = 0;
            if (!GuestRead64(asm_list + ai * 8, &asm_ptr)) continue;
            if (!asm_ptr || asm_ptr >= GUEST_RAM_BYTES) continue;

            uint64_t image_ptr = 0;
            if (!GuestRead64(asm_ptr, &image_ptr)) continue;
            if (!image_ptr || image_ptr >= GUEST_RAM_BYTES) continue;

            uint64_t img_name_ptr = 0;
            GuestRead64(image_ptr, &img_name_ptr);
            if (!img_name_ptr || img_name_ptr >= GUEST_RAM_BYTES) continue;

            std::string img_name = GuestReadStr(img_name_ptr, 128);
            bool is_game = (img_name.find("Assembly-CSharp") != std::string::npos ||
                            img_name.find("SubwaySurfers")   != std::string::npos ||
                            img_name.find("SYBO")            != std::string::npos);

            if (!is_game && ai < 5)
                LOG("  image[%llu] = \"%s\" (skipping)", (unsigned long long)ai, img_name.c_str());
            if (!is_game) continue;

            LOG("  image[%llu] = \"%s\" — falling through to brute-force for this image",
                (unsigned long long)ai, img_name.c_str());
            break;
        }
    }

    // ── Brute-force class scan ────────────────────────────────────────────────
    // Scan guest RAM [0x40000000, end) for Il2CppClass objects with field_count=99.
    // Filter: fields[40].name == "currentLane" AND fields[83].name == "laneIndex"
    LOG("brute-force class scan for field_count=99 ...");

    for (RTGCPHYS gpa = 0x40000000ULL; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  scan progress: GPA=%016llX", (unsigned long long)gpa);

        uint32_t fc = 0;
        if (!ReadClassFieldCount(gpa, &fc)) continue;

        uint64_t fields_ptr = 0;
        if (!GuestRead64(gpa + CLASS_OFF_FIELDS, &fields_ptr)) continue;
        if (!fields_ptr || fields_ptr >= GUEST_RAM_BYTES || (fields_ptr & 7)) continue;

        uint32_t off40 = 0, off83 = 0;
        if (!TryReadFieldOffset(fields_ptr, 40, "currentLane", &off40)) continue;
        if (!TryReadFieldOffset(fields_ptr, 83, "laneIndex",   &off83)) continue;

        uint64_t name_ptr = 0;
        GuestRead64(gpa + CLASS_OFF_NAME, &name_ptr);
        std::string cls_name = (name_ptr && name_ptr < GUEST_RAM_BYTES)
                               ? GuestReadStr(name_ptr, 128) : "<unknown>";

        uint64_t ns_ptr = 0;
        GuestRead64(gpa + CLASS_OFF_NAMESPACE, &ns_ptr);
        std::string ns_name = (ns_ptr && ns_ptr < GUEST_RAM_BYTES)
                              ? GuestReadStr(ns_ptr, 128) : "<unknown>";

        LOG("FOUND class \"%s\" in \"%s\" @ GPA=%016llX",
            cls_name.c_str(), ns_name.c_str(), (unsigned long long)gpa);
        LOG("  currentLane byte_offset = %u (0x%X)", off40, off40);
        LOG("  laneIndex   byte_offset = %u (0x%X)", off83, off83);

        res.currentLane_offset = off40;
        res.laneIndex_offset   = off83;
        res.class_gpa          = gpa;
        res.ok                 = true;
        return res;
    }

    LOG("class not found in guest RAM");
    return res;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 6 — Find a live CharacterInputController instance
// ═══════════════════════════════════════════════════════════════════════════════
//
// Every IL2CPP object starts with a pointer to its Il2CppClass (vtable pointer).
// Scan guest RAM for 8-byte aligned pointers equal to class_gpa.
// Filter: int32 at [obj + currentLane_offset] ∈ {-1, 0, 1}
//         int32 at [obj + laneIndex_offset]   ∈ {-1, 0, 1}

static RTGCPHYS FindLaneGPA(const FieldResult& fields)
{
    LOG("scanning for live instances (vtable @ GPA=%016llX) ...",
        (unsigned long long)fields.class_gpa);

    uint64_t found = 0;
    for (RTGCPHYS gpa = 0x40000000ULL; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  instance scan: GPA=%016llX", (unsigned long long)gpa);

        uint64_t vtable = 0;
        if (!GuestRead64(gpa, &vtable)) continue;
        if (vtable != fields.class_gpa) continue;

        RTGCPHYS lane_gpa = gpa + fields.currentLane_offset;
        int32_t lane_val = 0;
        if (!GuestRead(lane_gpa, &lane_val, 4)) continue;
        if (lane_val < -1 || lane_val > 1) continue;

        int32_t idx_val = 0;
        if (!GuestRead(gpa + fields.laneIndex_offset, &idx_val, 4)) continue;
        if (idx_val < -1 || idx_val > 1) continue;

        LOG("instance candidate @ GPA=%016llX  currentLane=%d  laneIndex=%d",
            (unsigned long long)gpa, lane_val, idx_val);
        found++;

        if (found == 1) {
            LOG("LANE_GPA = %016llX  (currentLane field)", (unsigned long long)lane_gpa);
            return lane_gpa;
        }
    }

    if (!found)
        LOG("no live instances found — game may not be running a run");
    return (RTGCPHYS)-1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 7 — Bot read loop
// ═══════════════════════════════════════════════════════════════════════════════

static void BotLoop(RTGCPHYS lane_gpa)
{
    LOG("entering bot loop  LANE_GPA=%016llX", (unsigned long long)lane_gpa);
    LOG("reading lane every 16ms — game close or process exit to stop");

    int32_t prev_lane = 999;
    int loop = 0;
    while (true) {
        int32_t lane = -99;
        bool ok = GuestRead(lane_gpa, &lane, 4);
        if (!ok) {
            LOG("[loop %6d] read failed", loop);
        } else if (lane != prev_lane) {
            LOG("[loop %6d] LANE = %d", loop, lane);
            prev_lane = lane;

            if      (lane == -1) LOG("  -> move LEFT");
            else if (lane ==  0) LOG("  -> CENTER");
            else if (lane ==  1) LOG("  -> move RIGHT");
        }
        loop++;
        Sleep(16);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main thread
// ═══════════════════════════════════════════════════════════════════════════════

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);
    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon v10] fopen failed\n"); return 0; }
    LOG("v10  — autonomous IL2CPP lane resolver");

    // Stage 1
    LOG("=== STAGE 1: VBox bridge ===");
    if (!InitVBoxBridge()) goto done;
    if (!ScanForUVM())     goto done;

    // Stage 2
    LOG("=== STAGE 2: guest RAM range map ===");
    if (!InitRangeMap()) goto done;

    // ── DIRECT_LANE_GPA bypass ────────────────────────────────────────────────
    // If DIRECT_LANE_GPA is set, skip stages 3-6 and go straight to the bot loop.
    // Use this while the full self-discovery path is being debugged:
    //   1. Run v10 once (DIRECT_LANE_GPA=0) to get the HCPtrStart logged in Stage 2.
    //   2. Compute GPA = CE_HVA - HCPtrStart  (CE_HVA = the address CE shows).
    //   3. Set DIRECT_LANE_GPA = that GPA value and recompile.
#if DIRECT_LANE_GPA != 0
    {
        LOG("=== DIRECT_LANE_GPA bypass: GPA=%016llX ===",
            (unsigned long long)(RTGCPHYS)DIRECT_LANE_GPA);
        // Quick sanity read
        int32_t v = -99;
        if (GuestRead((RTGCPHYS)DIRECT_LANE_GPA, &v, 4))
            LOG("  current lane value = %d", v);
        else
            LOG("  WARNING: read failed — check GPA or start a run first");
        BotLoop((RTGCPHYS)DIRECT_LANE_GPA);
        goto done;
    }
#endif

    {
        // Stage 3
        LOG("=== STAGE 3: ELF scan ===");
        RTGCPHYS elfBase = FindLibIl2CppBase();
        if (elfBase == (RTGCPHYS)-1) goto done;

        // Stage 4
        LOG("=== STAGE 4: export RVAs ===");
        Il2CppExports exp = ReadIl2CppExports(elfBase);

        // Stage 5
        LOG("=== STAGE 5: field offset discovery ===");
        FieldResult fields = FindLaneFields(elfBase, exp);
        if (!fields.ok) {
            LOG("field discovery failed");
            goto done;
        }

        // Stage 6
        LOG("=== STAGE 6: instance scan ===");
        RTGCPHYS lane_gpa = FindLaneGPA(fields);
        if (lane_gpa == (RTGCPHYS)-1) {
            LOG("no live instance — start a run then re-inject");
            goto done;
        }

        // Stage 7
        LOG("=== STAGE 7: bot loop ===");
        BotLoop(lane_gpa);
    }

done:
    LOG("exiting");
    if (g_log) { fclose(g_log); g_log = nullptr; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, ReconThread, nullptr, 0, nullptr);
    return TRUE;
}