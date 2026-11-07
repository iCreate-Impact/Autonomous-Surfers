/*
 * recon.dll  v9  — full self-discovering IL2CPP lane resolver
 *
 * Architecture:
 *   1.  Resolve pUVM/pVM from BstkVMM.dll (unchanged from v8)
 *   2.  Walk guest RAM (GPA 0..3584MB) scanning for the libil2cpp.so ELF base
 *   3.  Parse ELF dynsym table (all in guest RAM via PGMPhysSimpleReadGCPhys)
 *       to get RVAs for the il2cpp_* exports we need
 *   4.  Those exports are real ARM64 code — we can't call them from x86-64.
 *       Instead we READ the class/field metadata the same way the exports
 *       would: by following the in-memory IL2CPP object graph directly.
 *         Il2CppDomain  →  Assembly[]  →  Image  →  Class[]
 *         For each class: read field table, match names "currentLane"/"laneIndex"
 *         When found: read the field's byte offset from the FieldInfo struct
 *   5.  Scan guest RAM for live CharacterInputController-like instances:
 *         vtable pointer at [obj+0] == libil2cpp_base + vtable_rva
 *         int32 at [obj + field_offset] ∈ {-1, 0, 1}
 *   6.  Confirm by switching lanes in-game and watching which GPA flips
 *   7.  Read LANE_GPA every 16 ms for the bot loop
 *
 * NOTE: Steps 2-6 happen entirely through guest RAM reads.
 *       No ARM64 code is ever executed on the host.
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
static uint64_t g_gpaBase = 0;   // GCPhys start  (should be 0)

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

// Read a null-terminated string from guest RAM (capped at max_len)
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

// After InitRangeMap() we can convert HVAs to GPAs in O(1)
// (BlueStacks guest is one flat range, confirmed in v8)

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
// STAGE 1 — VBox bridge (unchanged from v8)
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
// STAGE 2 — Map the flat guest RAM range to find HVA base
// ═══════════════════════════════════════════════════════════════════════════════
//
// Walk pVM+0x1010 linked list; find the range covering GPA 0x00000000.
// BlueStacks has one flat range 0x0..0xDFFFFFFF, so this is range[0].

static bool InitRangeMap()
{
    uintptr_t headPtr = 0;
    __try { headPtr = *(uintptr_t*)((uintptr_t)g_pVM + PGM_RANGES_OFFSET); }
    __except(EXCEPTION_EXECUTE_HANDLER) { LOG("pVM+0x1010 read threw"); return false; }

    if (!headPtr) { LOG("pRamRangesXR3 is null"); return false; }
    LOG("pRamRangesXR3 = %p", (void*)headPtr);

    // Find pNextR3 offset by scanning the first node for a pointer-aligned
    // slot that is null or points to memory whose first uint64 is a small GPA.
    Prefault((void*)headPtr, 0x200);
    uint32_t nextOff = 0;
    for (uint32_t off = 0x20; off <= 0x100; off += 8) {
        uintptr_t candidate = 0;
        __try { candidate = *(uintptr_t*)(headPtr + off); }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (candidate == 0) { if (!nextOff) nextOff = off; break; } // null = end of list
        if ((candidate >> 48) != 0 && (candidate >> 48) != 0xFFFF) continue;
        uint64_t t0 = 0;
        __try { t0 = *(uint64_t*)candidate; } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (t0 == 0 || (t0 < 0x100000000ULL && (t0 & 0xFFF) == 0)) {
            if (!nextOff) nextOff = off;
            break;
        }
    }
    if (!nextOff) nextOff = 0x38; // fallback; stock VBox 6.x value
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

        // The main guest RAM range starts at GPA 0 and covers ~3584 MB
        if (gcStart == 0 && sz >= 0x10000000ULL) {
            g_hvaBase = hcPtr;
            g_gpaBase = gcStart;
            LOG("guest RAM base: HVA=%016llX  GPA=%016llX  size=%.2f GB",
                (unsigned long long)hcPtr,
                (unsigned long long)gcStart,
                sz / (1024.0 * 1024.0 * 1024.0));
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
// ARM64 Android: libil2cpp.so loads somewhere in the 0x6xxxxxxx or similar
// user-space range. We scan page-aligned GPAs for the ELF magic \x7fELF,
// then confirm it's a 64-bit ARM shared object.

static const uint8_t ELF_MAGIC[4] = { 0x7f, 'E', 'L', 'F' };

// ELF64 header fields we care about (little-endian ARM64)
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

struct Elf64Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

static RTGCPHYS FindLibIl2CppBase()
{
    LOG("scanning guest RAM for libil2cpp.so ELF header ...");
    LOG("(this may take 30-60 seconds over 3584 MB)");

    // libil2cpp.so is 81 MB; it loads well above 0x6000_0000 on Android 10+
    // Start at 0x6000_0000, step by 4 KB pages.
    // We look for: ELF magic + ET_DYN + EM_AARCH64 + reasonable e_shnum

    // Optimization: read 4 KB chunks and check magic at offset 0.
    // We only do the full header read on magic hits.
    uint8_t page[16];

    for (RTGCPHYS gpa = 0x60000000ULL; gpa < GUEST_RAM_BYTES; gpa += 0x1000) {
        if (!GuestRead(gpa, page, 16)) continue;
        if (memcmp(page, ELF_MAGIC, 4) != 0) continue;
        if (page[4] != 2) continue; // EI_CLASS = ELFCLASS64
        if (page[5] != 1) continue; // EI_DATA  = ELFDATA2LSB

        Elf64Hdr hdr;
        if (!GuestRead(gpa, &hdr, sizeof(hdr))) continue;
        if (hdr.e_type    != 3)   continue; // ET_DYN
        if (hdr.e_machine != 183) continue; // EM_AARCH64
        if (hdr.e_shnum   < 10 || hdr.e_shnum > 2000) continue;
        if (hdr.e_shentsize != sizeof(Elf64Shdr)) continue;

        // Found a 64-bit ARM shared object — verify it has il2cpp exports
        // by reading the section header string table and looking for ".dynsym"
        if (hdr.e_shstrndx == 0 || hdr.e_shstrndx >= hdr.e_shnum) continue;

        RTGCPHYS shstrHdr_gpa = gpa + hdr.e_shoff + (uint64_t)hdr.e_shstrndx * sizeof(Elf64Shdr);
        Elf64Shdr shstrHdr;
        if (!GuestRead(shstrHdr_gpa, &shstrHdr, sizeof(shstrHdr))) continue;
        if (shstrHdr.sh_size > 0x20000 || shstrHdr.sh_size == 0) continue;

        // Check a section named ".dynsym" exists
        bool hasDynsym = false;
        for (uint16_t si = 0; si < hdr.e_shnum && !hasDynsym; si++) {
            Elf64Shdr sh;
            RTGCPHYS sh_gpa = gpa + hdr.e_shoff + (uint64_t)si * sizeof(Elf64Shdr);
            if (!GuestRead(sh_gpa, &sh, sizeof(sh))) continue;
            if (sh.sh_type != 11) continue; // SHT_DYNSYM
            hasDynsym = true;
        }
        if (!hasDynsym) continue;

        LOG("ELF candidate @ GPA=%016llX  e_shnum=%u — checking exports ...",
            (unsigned long long)gpa, hdr.e_shnum);

        // Final confirmation: look for "il2cpp_domain_get" in dynsym strtab
        // If found this is definitely libil2cpp.so
        for (uint16_t si = 0; si < hdr.e_shnum; si++) {
            Elf64Shdr sh;
            RTGCPHYS sh_gpa = gpa + hdr.e_shoff + (uint64_t)si * sizeof(Elf64Shdr);
            if (!GuestRead(sh_gpa, &sh, sizeof(sh))) continue;
            if (sh.sh_type != 11) continue; // SHT_DYNSYM

            uint32_t strtab_idx = sh.sh_link;
            if (strtab_idx >= hdr.e_shnum) continue;

            Elf64Shdr strtabHdr;
            RTGCPHYS strtab_sh_gpa = gpa + hdr.e_shoff + (uint64_t)strtab_idx * sizeof(Elf64Shdr);
            if (!GuestRead(strtab_sh_gpa, &strtabHdr, sizeof(strtabHdr))) continue;

            uint64_t nSyms = sh.sh_size / sizeof(Elf64Sym);
            if (nSyms > 50000) continue;

            for (uint64_t sym_i = 0; sym_i < nSyms; sym_i++) {
                Elf64Sym sym;
                RTGCPHYS sym_gpa = gpa + sh.sh_offset + sym_i * sizeof(Elf64Sym);
                if (!GuestRead(sym_gpa, &sym, sizeof(sym))) continue;

                RTGCPHYS name_gpa = gpa + strtabHdr.sh_offset + sym.st_name;
                std::string name = GuestReadStr(name_gpa, 32);
                if (name == "il2cpp_domain_get") {
                    LOG("CONFIRMED libil2cpp.so @ GPA=%016llX  il2cpp_domain_get RVA=%016llX",
                        (unsigned long long)gpa, (unsigned long long)sym.st_value);
                    return gpa;
                }
            }
        }
    }
    LOG("libil2cpp.so not found in guest RAM");
    return (RTGCPHYS)-1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 4 — Read IL2CPP export RVAs from dynsym
// ═══════════════════════════════════════════════════════════════════════════════

struct Il2CppExports {
    uint64_t domain_get;             // il2cpp_domain_get
    uint64_t domain_get_assemblies;  // il2cpp_domain_get_assemblies
    uint64_t class_from_name;        // il2cpp_class_from_name
    uint64_t class_get_field_from_name; // il2cpp_class_get_field_from_name
    uint64_t class_get_fields;       // il2cpp_class_get_fields
    uint64_t class_num_fields;       // il2cpp_class_num_fields
    uint64_t field_get_offset;       // il2cpp_field_get_offset
    uint64_t field_get_name;         // il2cpp_field_get_name
    uint64_t assembly_get_image;     // il2cpp_assembly_get_image
    uint64_t image_get_class;        // il2cpp_image_get_class
    uint64_t image_get_class_count;  // il2cpp_image_get_class_count
    bool ok;
};

static Il2CppExports ReadIl2CppExports(RTGCPHYS elfBase)
{
    Il2CppExports exp = {};
    Elf64Hdr hdr;
    if (!GuestRead(elfBase, &hdr, sizeof(hdr))) return exp;

    for (uint16_t si = 0; si < hdr.e_shnum; si++) {
        Elf64Shdr sh;
        RTGCPHYS sh_gpa = elfBase + hdr.e_shoff + (uint64_t)si * sizeof(Elf64Shdr);
        if (!GuestRead(sh_gpa, &sh, sizeof(sh))) continue;
        if (sh.sh_type != 11) continue; // SHT_DYNSYM

        uint32_t strtab_idx = sh.sh_link;
        if (strtab_idx >= hdr.e_shnum) continue;
        Elf64Shdr strtabHdr;
        RTGCPHYS strtab_sh_gpa = elfBase + hdr.e_shoff + (uint64_t)strtab_idx * sizeof(Elf64Shdr);
        if (!GuestRead(strtab_sh_gpa, &strtabHdr, sizeof(strtabHdr))) continue;

        uint64_t nSyms = sh.sh_size / sizeof(Elf64Sym);
        for (uint64_t sym_i = 0; sym_i < nSyms; sym_i++) {
            Elf64Sym sym;
            RTGCPHYS sym_gpa = elfBase + sh.sh_offset + sym_i * sizeof(Elf64Sym);
            if (!GuestRead(sym_gpa, &sym, sizeof(sym))) continue;
            if (sym.st_value == 0) continue;

            RTGCPHYS name_gpa = elfBase + strtabHdr.sh_offset + sym.st_name;
            std::string name = GuestReadStr(name_gpa, 64);

            if      (name == "il2cpp_domain_get")              exp.domain_get              = sym.st_value;
            else if (name == "il2cpp_domain_get_assemblies")   exp.domain_get_assemblies   = sym.st_value;
            else if (name == "il2cpp_class_from_name")         exp.class_from_name         = sym.st_value;
            else if (name == "il2cpp_class_get_field_from_name") exp.class_get_field_from_name = sym.st_value;
            else if (name == "il2cpp_class_get_fields")        exp.class_get_fields        = sym.st_value;
            else if (name == "il2cpp_class_num_fields")        exp.class_num_fields        = sym.st_value;
            else if (name == "il2cpp_field_get_offset")        exp.field_get_offset        = sym.st_value;
            else if (name == "il2cpp_field_get_name")          exp.field_get_name          = sym.st_value;
            else if (name == "il2cpp_assembly_get_image")      exp.assembly_get_image      = sym.st_value;
            else if (name == "il2cpp_image_get_class")         exp.image_get_class         = sym.st_value;
            else if (name == "il2cpp_image_get_class_count")   exp.image_get_class_count   = sym.st_value;
        }
        break; // only one SHT_DYNSYM section
    }

    exp.ok = exp.domain_get && exp.field_get_offset && exp.field_get_name;
    if (exp.ok)
        LOG("exports resolved: domain_get=RVA+%llX  field_get_offset=RVA+%llX",
            (unsigned long long)exp.domain_get,
            (unsigned long long)exp.field_get_offset);
    else
        LOG("WARNING: some exports missing (domain_get=%llu field_get_offset=%llu)",
            (unsigned long long)exp.domain_get,
            (unsigned long long)exp.field_get_offset);
    return exp;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 5 — Walk IL2CPP object graph in guest RAM to find field offsets
// ═══════════════════════════════════════════════════════════════════════════════
//
// IL2CPP internal layout (ARM64, metadata v29-31, Unity 2020-2022):
//
//   il2cpp_domain_get() → Il2CppDomain* (a pointer in libil2cpp .bss/.data)
//   The exported symbol's VALUE in dynsym is an RVA into libil2cpp.so.
//   At runtime the domain pointer lives at elfBase + domain_get_rva (a GOT slot
//   or data address — the symbol st_value IS the address of the domain pointer).
//
//   Il2CppDomain (simplified):
//     +0x00  void*         setup_name  (usually "IL2CPP Root Domain")
//     +0x10  Il2CppAssembly**  assemblies
//     +0x18  size_t            assemblies_count  (varies; we scan for it)
//
//   Il2CppAssembly:
//     +0x00  Il2CppImage*  image
//
//   Il2CppImage:
//     +0x00  char*                name
//     +0x08  char*                assembly_name
//     +0x10  Il2CppImageDefinitionData* data  (points into metadata; skip)
//     ...
//     We use the exported APIs conceptually; we read the C struct directly.
//     The key struct for us: each class object is an Il2CppClass*.
//
//   Il2CppClass (ARM64, metadata v31, Unity ~2021):
//     +0x00  Il2CppImage*            image
//     +0x08  void*                   gc_desc
//     +0x10  char*                   name
//     +0x18  char*                   namespaze
//     +0x20  Il2CppType             byval_arg
//     +0x30  Il2CppType             this_arg
//     +0x40  Il2CppClass*           element_class
//     +0x48  Il2CppClass*           castClass
//     +0x50  Il2CppClass*           declaringType
//     +0x58  Il2CppClass*           parent
//     +0x60  ... (generic container, interfaces, etc.)
//     fields are accessed via:
//       Il2CppFieldInfo*  fields  — pointer to array of FieldInfo
//       uint16_t          field_count
//
//   We'll locate these by scanning candidate class pointers.
//   The robust path: use image → class table, read each class's field array,
//   match by field name strings.
//
// In practice the safest approach without calling ARM64 code:
//
//   1. The domain pointer is a DATA symbol in dynsym — st_value is the GPA
//      (after adding elfBase) of a pointer-sized slot holding the Il2CppDomain*.
//      Read [elfBase + domain_rva] → Il2CppDomain GPA.
//
//   2. Walk Il2CppDomain to get assembly count + assembly list.
//      Layout differs by Unity version; we probe common offsets.
//
//   3. For each assembly → image → iterate classes using the class registration
//      table. The easiest hook: Il2CppMetadataRegistration contains a pointer
//      to the type array; but that's deep.
//
//   SIMPLER: We know from offline analysis:
//     - typedef[4765], fs=2964, fc=99 (99 fields)
//     - field[40 within class] = "currentLane"  (abs_fi 3004)
//     - field[83 within class] = "liveIndex"    (abs_fi 3047)
//   This is METADATA — it doesn't change at runtime.
//   The FIELD BYTE OFFSET within the object is in the FieldInfo array.
//
//   Il2CppFieldInfo (ARM64):
//     +0x00  char*    name
//     +0x08  Il2CppType* type
//     +0x10  uint32_t  offset   (byte offset within object, includes 0x10 object header)
//     +0x14  uint32_t  token
//     NOTE: for static fields offset = 0xFFFFFFFF (sentinel)
//
//   STRATEGY:
//   Walk guest RAM class list via the image→typeStart table.
//   For each class whose field_count == 99:
//     Read fields[40].name → check == "currentLane"
//     Read fields[83].name → check == "laneIndex"
//     If both match: grab fields[40].offset and fields[83].offset
//     Also grab: class→vtable pointer (for instance scanning)

struct FieldResult {
    uint32_t currentLane_offset;  // byte offset within object
    uint32_t laneIndex_offset;
    uint64_t vtable_rva;          // vtable RVA within libil2cpp.so (for instance scan)
    uint64_t class_gpa;
    bool ok;
};

// Il2CppClass layout offsets we probe (ARM64, Unity 2020-2022, metadata v31)
// These are well-known from public IL2CPP source / reversing:
static const uint32_t CLASS_OFF_NAME       = 0x10;
static const uint32_t CLASS_OFF_NAMESPACE  = 0x18;
static const uint32_t CLASS_OFF_FIELDS     = 0x80; // Il2CppFieldInfo* fields
static const uint32_t CLASS_OFF_FIELDCOUNT = 0xBC; // uint16_t field_count (varies 0xBC-0xC4)
static const uint32_t CLASS_OFF_VTABLE     = 0xD0; // start of vtable array (varies)
// FieldInfo offsets:
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

    // name_ptr is a GPA (we're reading guest RAM)
    std::string fname = GuestReadStr(name_ptr, 64);
    if (fname != expected_name) return false;

    uint32_t byte_off = 0;
    if (!GuestRead32(fgpa + FIELD_OFF_OFFSET, &byte_off)) return false;
    if (byte_off == 0xFFFFFFFF || byte_off > 0x10000) return false; // static / sanity

    *out_offset = byte_off;
    return true;
}

// Try multiple known field_count offsets for a class — layout varies by Unity version
static bool ReadClassFieldCount(RTGCPHYS class_gpa, uint32_t* out_count)
{
    // Try the most common offsets first
    static const uint32_t offsets[] = { 0xBC, 0xB8, 0xC0, 0xC4, 0x88, 0x90 };
    for (auto off : offsets) {
        uint32_t v = 0;
        // field_count is uint16_t but reading uint32 is safe; low 16 bits are the count
        if (!GuestRead32(class_gpa + off, &v)) continue;
        uint16_t fc = (uint16_t)(v & 0xFFFF);
        if (fc == 99) { *out_count = fc; return true; }
    }
    return false;
}

static FieldResult FindLaneFields(RTGCPHYS elfBase,
                                   const Il2CppExports& /*exp — not called, just for reference*/)
{
    FieldResult res = {};

    // The IL2CPP runtime registers all types in a global type list.
    // We read it from the .data segment indirectly by scanning for
    // class objects whose field_count == 99.
    //
    // Scan range: 0x6000_0000 .. g_gpaBase+GUEST_RAM_BYTES
    // We need class GPA candidates. Class objects in IL2CPP are heap-allocated
    // and typically 8-byte aligned, 0x100-0x200 bytes in size.
    //
    // Faster heuristic: scan for the vtable of MonoBehaviour subclasses.
    // Even faster: use the assembly/image class list.
    //
    // We'll do the class list walk using IL2CPP internal metadata pointers.
    //
    // Il2CppCodeRegistration and Il2CppMetadataRegistration are anchored via
    // well-known export "il2cpp_domain_get" which returns a singleton.
    // The domain is at [elfBase + domain_get_rva] as a GPA pointer.

    // Read domain pointer
    // domain_get RVA points to the function, but the domain itself is in .bss/.data
    // On ARM64 the function body starts with something like:
    //   ADRP x0, page_containing_domain_global
    //   LDR  x0, [x0, #offset]
    //   RET
    // We can read the function bytes and decode the ADRP+LDR to find the global.
    // But that's fragile. Simpler: scan the data segment for the domain object.
    //
    // Il2CppDomain is identifiable because:
    //   [+0x00] char* → "IL2CPP Root Domain" or similar
    //   [+0x10] Il2CppAssembly** → pointer into heap
    //
    // We'll scan the libil2cpp.so data section for a pointer whose target
    // string starts with "IL2CPP".

    LOG("scanning for Il2CppDomain ...");

    // libil2cpp.so is ~81 MB starting at elfBase. Data segment is in the second half.
    // Scan from elfBase+0x2000000 (32 MB in) to elfBase+0x5000000 for domain ptr.
    // The domain pointer itself is a 8-byte aligned GPA.
    RTGCPHYS domain_gpa = 0;

    for (RTGCPHYS off = 0x2000000; off < 0x5000000 && !domain_gpa; off += 8) {
        RTGCPHYS scan_gpa = elfBase + off;
        if (scan_gpa + 8 > GUEST_RAM_BYTES) break;

        uint64_t ptr = 0;
        if (!GuestRead64(scan_gpa, &ptr)) continue;
        if (ptr == 0 || ptr >= GUEST_RAM_BYTES || (ptr & 7)) continue;

        // Check if [ptr+0x00] is a readable pointer whose target is a string "IL2CPP"
        uint64_t name_ptr = 0;
        if (!GuestRead64(ptr, &name_ptr)) continue;
        if (name_ptr == 0 || name_ptr >= GUEST_RAM_BYTES) continue;

        uint8_t str_start[8] = {};
        if (!GuestRead(name_ptr, str_start, 7)) continue;
        if (memcmp(str_start, "IL2CPP", 6) != 0) continue;

        // Plausible domain — check assemblies pointer at +0x10
        uint64_t asm_list = 0;
        if (!GuestRead64(ptr + 0x10, &asm_list)) continue;
        if (asm_list == 0 || asm_list >= GUEST_RAM_BYTES || (asm_list & 7)) continue;

        std::string domain_name = GuestReadStr(name_ptr, 64);
        LOG("Il2CppDomain candidate @ GPA=%016llX  name=\"%s\"",
            (unsigned long long)ptr, domain_name.c_str());
        domain_gpa = ptr;
    }

    if (!domain_gpa) {
        LOG("Il2CppDomain not found — trying fallback field scan");
        // Fallback: brute-force scan all of guest RAM for class objects with fc=99
        // and matching field names. Slower but guaranteed.
        goto field_brute_force;
    }

    {
        // Read assembly list
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

            // Il2CppAssembly[0] = Il2CppImage* image
            uint64_t image_ptr = 0;
            if (!GuestRead64(asm_ptr, &image_ptr)) continue;
            if (!image_ptr || image_ptr >= GUEST_RAM_BYTES) continue;

            // Il2CppImage: +0x00 char* name, +0x08 char* assembly_name
            uint64_t img_name_ptr = 0;
            GuestRead64(image_ptr, &img_name_ptr);
            if (!img_name_ptr || img_name_ptr >= GUEST_RAM_BYTES) continue;

            std::string img_name = GuestReadStr(img_name_ptr, 128);

            // The class we want is in the main game assembly
            // Look for "Assembly-CSharp" or anything SYBO-related
            bool is_game = (img_name.find("Assembly-CSharp") != std::string::npos ||
                            img_name.find("SubwaySurfers")   != std::string::npos ||
                            img_name.find("SYBO")            != std::string::npos);

            if (!is_game && ai < 5)
                LOG("  image[%llu] = \"%s\" (skipping)", (unsigned long long)ai, img_name.c_str());
            if (!is_game) continue;

            LOG("  image[%llu] = \"%s\" (scanning classes ...)",
                (unsigned long long)ai, img_name.c_str());

            // Il2CppImage class table: at +0x44 (or nearby) is typeStart (uint32_t),
            // at +0x48 is typeCount. These index into the global s_Il2CppTypeDefinitions array.
            // The class pointer array: in older Unity it's image->typeStart into
            // s_Il2CppMetadataRegistration.typeDefinitions[typeStart + i]
            //
            // Easier: iterate via the image's internal class hash table.
            // Even easier: we know the assembly is "Assembly-CSharp".
            // Look for class objects in the whole image range.
            // For now, fall through to brute force for this image's class range.
            // The brute force is fast enough since we filter by field_count=99.
            break;
        }
    }

field_brute_force:
    // Scan all of guest RAM for class objects with field_count == 99
    // A class object is 8-byte aligned, starts with an Il2CppImage* pointer.
    // We filter by field_count == 99 first (cheap), then verify field names.
    LOG("brute-force class scan for field_count=99 ...");

    uint64_t scanned = 0;
    for (RTGCPHYS gpa = 0x40000000ULL; gpa < GUEST_RAM_BYTES; gpa += 8, scanned++) {
        // Log progress every 256 MB
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  scan progress: GPA=%016llX", (unsigned long long)gpa);

        uint32_t fc = 0;
        if (!ReadClassFieldCount(gpa, &fc)) continue; // fc != 99

        // field_count == 99; check fields pointer
        uint64_t fields_ptr = 0;
        if (!GuestRead64(gpa + CLASS_OFF_FIELDS, &fields_ptr)) continue;
        if (!fields_ptr || fields_ptr >= GUEST_RAM_BYTES || (fields_ptr & 7)) continue;

        // Check field[40] name == "currentLane"
        uint32_t off40 = 0, off83 = 0;
        if (!TryReadFieldOffset(fields_ptr, 40, "currentLane", &off40)) continue;
        if (!TryReadFieldOffset(fields_ptr, 83, "laneIndex",   &off83)) continue;

        // Double-check: read the class name
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

    LOG("class not found in guest RAM (scanned %llu slots)", (unsigned long long)scanned);
    return res;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 6 — Find a live CharacterInputController instance
// ═══════════════════════════════════════════════════════════════════════════════
//
// Every IL2CPP object starts with a pointer to its Il2CppClass (the vtable pointer).
// So we scan guest RAM for 8-byte aligned pointers equal to class_gpa.
// Filter: int32 at [obj + currentLane_offset] ∈ {-1, 0, 1}
//
// Returns the GPA of the currentLane field within the first valid instance.

static RTGCPHYS FindLaneGPA(const FieldResult& fields)
{
    LOG("scanning guest RAM for live class instances (vtable @ GPA=%016llX) ...",
        (unsigned long long)fields.class_gpa);

    uint64_t found = 0;
    for (RTGCPHYS gpa = 0x40000000ULL; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  instance scan: GPA=%016llX", (unsigned long long)gpa);

        uint64_t vtable = 0;
        if (!GuestRead64(gpa, &vtable)) continue;
        if (vtable != fields.class_gpa) continue;

        // Candidate object: check currentLane ∈ {-1, 0, 1}
        RTGCPHYS lane_gpa = gpa + fields.currentLane_offset;
        int32_t lane_val = 0;
        if (!GuestRead(lane_gpa, &lane_val, 4)) continue;
        if (lane_val < -1 || lane_val > 1) continue;

        // Also check laneIndex ∈ {-1, 0, 1}
        int32_t idx_val = 0;
        if (!GuestRead(gpa + fields.laneIndex_offset, &idx_val, 4)) continue;
        if (idx_val < -1 || idx_val > 1) continue;

        LOG("instance candidate @ GPA=%016llX  currentLane=%d  laneIndex=%d",
            (unsigned long long)gpa, lane_val, idx_val);
        found++;

        if (found == 1) {
            // Return the first valid instance's lane field GPA
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
    LOG("reading lane every 16ms — Ctrl+C or game close to stop");

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

            // ── bot decision ──────────────────────────────────────────────
            // TODO: replace with actual swipe injection.
            // For now just log the transitions.
            if      (lane == -1) LOG("  → move LEFT");
            else if (lane ==  0) LOG("  → CENTER");
            else if (lane ==  1) LOG("  → move RIGHT");
            // ─────────────────────────────────────────────────────────────
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
    if (!g_log) { OutputDebugStringA("[recon v9] fopen failed\n"); return 0; }
    LOG("v9  — autonomous IL2CPP lane resolver");

    // Stage 1 — VBox bridge
    LOG("=== STAGE 1: VBox bridge ===");
    if (!InitVBoxBridge()) goto done;
    if (!ScanForUVM())     goto done;

    // Stage 2 — Map guest RAM range (need HVA base)
    LOG("=== STAGE 2: guest RAM range map ===");
    if (!InitRangeMap()) goto done;

    {
        // Stage 3 — Find libil2cpp.so
        LOG("=== STAGE 3: ELF scan ===");
        RTGCPHYS elfBase = FindLibIl2CppBase();
        if (elfBase == (RTGCPHYS)-1) goto done;

        // Stage 4 — Read exports (for logging; offsets used in stage 5)
        LOG("=== STAGE 4: export RVAs ===");
        Il2CppExports exp = ReadIl2CppExports(elfBase);

        // Stage 5 — Find field byte offsets via class scan
        LOG("=== STAGE 5: field offset discovery ===");
        FieldResult fields = FindLaneFields(elfBase, exp);
        if (!fields.ok) {
            LOG("field discovery failed");
            goto done;
        }

        // Stage 6 — Find a live instance
        LOG("=== STAGE 6: instance scan ===");
        RTGCPHYS lane_gpa = FindLaneGPA(fields);
        if (lane_gpa == (RTGCPHYS)-1) {
            LOG("no live instance — start a run then re-inject");
            goto done;
        }

        // Stage 7 — Bot loop
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