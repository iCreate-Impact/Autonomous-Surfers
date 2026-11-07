/*
 * recon.dll  v11  — full self-discovering IL2CPP lane resolver
 *
 * Root cause fixed from v10:
 *   libil2cpp.so is 81 MB. Its physical pages are SCATTERED throughout guest RAM —
 *   not contiguous. Finding the ELF header page at GPA 0xC3E90000 and then reading
 *   PT_DYNAMIC at "elfBase + dyn_file_offset" doesn't work because those pages are
 *   elsewhere in physical memory.
 *
 * Fix: ARM64 3-level page table walk (GVA <-> GPA translation).
 *
 *   Step 1  FindLibIl2CppBase() — unchanged, finds ELF header GPA.
 *           Reads phdrs (always in first page): gets PT_DYNAMIC p_vaddr.
 *
 *   Step 2  FindTTBR0() — reverse PTE scan.
 *           Scans all guest RAM for an ARM64 PTE whose OA bits == ELF header GPA.
 *           Walks up: PTE page -> PMD -> PGD = TTBR0 (the process page table base).
 *           Recovers the GVA of the ELF header as a side effect.
 *
 *   Step 3  GvaToGpa() — standard 3-level ARM64 page table walk.
 *           Translates any GVA in the target process to a GPA.
 *
 *   Step 4  ReadIl2CppExports() — reads PT_DYNAMIC via GvaToGpa,
 *           then walks dynsym/strtab (each page translated individually).
 *
 * ARM64 Linux page table (39-bit VA, 4KB pages, 3 levels — Android default):
 *   PGD[VA[38:30]] -> PMD page GPA
 *   PMD[VA[29:21]] -> PTE page GPA
 *   PTE[VA[20:12]] -> physical page GPA
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
// Set to the GPA of the lane field (CE_HVA - HCPtrStart from Stage 2 log).
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
static const uint64_t GUEST_RAM_BYTES   = 0xE0000000ULL;

#define LOG_PATH "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;
static pfnPGMPhysSimpleReadGCPhys   g_fnRead;
static pfnPGMPhysSimpleWriteGCPhys  g_fnWrite;

static FILE*    g_log     = nullptr;
static void*    g_pVM     = nullptr;
static PUVM     g_pUVM    = nullptr;
static uint64_t g_hvaBase = 0;
static uint64_t g_gpaBase = 0;

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
    return rc == 0;
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

static void Prefault(void* base, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)base;
    size_t pages = (size + 0xFFF) / 0x1000;
    for (size_t i = 0; i < pages; i++)
        __try { (void)p[i * 0x1000]; } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

// ── ARM64 page table walk ─────────────────────────────────────────────────────
//
// 39-bit VA (Android default), 4KB pages, 3 levels.
//   VA[38:30] -> PGD index  (9 bits, 512 entries)
//   VA[29:21] -> PMD index  (9 bits, 512 entries)
//   VA[20:12] -> PTE index  (9 bits, 512 entries)
//   VA[11:0]  -> page offset
//
// A table descriptor (points to next-level page table):
//   bits[1:0]  = 11  (table)
//   bits[47:12] = output address (OA) of the next-level table page
//
// A page descriptor (leaf PTE, points to a physical page):
//   bits[1:0]  = 11  (page, not block; block = 01 at PGD/PMD level)
//   bits[47:12] = output address of the physical page (PFN << 12)
//   bit[10]    = AF (access flag; must be 1 for a touched page)
//
// We use the OA mask: 0x0000FFFFFFFFF000 for all levels.
// Valid page/table descriptor: (entry & 3) == 3.

static const uint64_t ARM64_OA_MASK  = 0x0000FFFFFFFFF000ULL;
static const uint64_t ARM64_VALID    = 0x3ULL;   // bits[1:0] = 11

static bool IsValidDescriptor(uint64_t e)
{
    return (e & ARM64_VALID) == ARM64_VALID &&
           (e & ARM64_OA_MASK) != 0 &&
           (e & ARM64_OA_MASK) < GUEST_RAM_BYTES;
}

// Translate GVA -> GPA using the 3-level ARM64 page table rooted at ttbr0.
// Returns false if any level is not mapped.
static bool GvaToGpa(uint64_t ttbr0, uint64_t gva, RTGCPHYS* out_gpa)
{
    uint64_t pgd_idx = (gva >> 30) & 0x1FF;
    uint64_t pmd_idx = (gva >> 21) & 0x1FF;
    uint64_t pte_idx = (gva >> 12) & 0x1FF;
    uint64_t pg_off  = gva & 0xFFF;

    // Level 0: PGD
    uint64_t pgd_e = 0;
    if (!GuestRead64(ttbr0 + pgd_idx * 8, &pgd_e)) return false;
    if (!IsValidDescriptor(pgd_e)) return false;
    uint64_t pmd_page = pgd_e & ARM64_OA_MASK;

    // Level 1: PMD
    uint64_t pmd_e = 0;
    if (!GuestRead64(pmd_page + pmd_idx * 8, &pmd_e)) return false;
    if (!IsValidDescriptor(pmd_e)) return false;

    // Check for 2MB block mapping at PMD level (bits[1:0] = 01 at this level
    // means block; but we already checked == 11, so it's a table -> PTE page).
    // Some kernels use 2MB blocks for .text. Handle that:
    if ((pmd_e & 0x3) == 0x1) {
        // 2MB block: OA is the 2MB-aligned PA
        uint64_t block_pa = pmd_e & 0xFFFFFFFE00000ULL; // bits[47:21]
        *out_gpa = block_pa | (gva & 0x1FFFFF);
        return *out_gpa < GUEST_RAM_BYTES;
    }
    uint64_t pte_page = pmd_e & ARM64_OA_MASK;

    // Level 2: PTE
    uint64_t pte_e = 0;
    if (!GuestRead64(pte_page + pte_idx * 8, &pte_e)) return false;
    if (!IsValidDescriptor(pte_e)) return false;

    *out_gpa = (pte_e & ARM64_OA_MASK) | pg_off;
    return *out_gpa < GUEST_RAM_BYTES;
}

// Read a string from guest VA space (translating each page as needed).
static std::string GvaReadStr(uint64_t ttbr0, uint64_t gva, size_t max_len = 256)
{
    std::string s;
    s.reserve(64);
    for (size_t i = 0; i < max_len; i++) {
        RTGCPHYS gpa = 0;
        if (!GvaToGpa(ttbr0, gva + i, &gpa)) break;
        uint8_t c = 0;
        if (!GuestRead(gpa, &c, 1)) break;
        if (c == 0) break;
        s += (char)c;
    }
    return s;
}

// Read N bytes from guest VA space (handles page boundaries).
static bool GvaRead(uint64_t ttbr0, uint64_t gva, void* dst, size_t cb)
{
    uint8_t* p = (uint8_t*)dst;
    for (size_t i = 0; i < cb; ) {
        RTGCPHYS gpa = 0;
        if (!GvaToGpa(ttbr0, gva + i, &gpa)) return false;
        // How much can we read from this page?
        size_t page_rem = 0x1000 - (gpa & 0xFFF);
        size_t chunk    = (cb - i < page_rem) ? (cb - i) : page_rem;
        if (!GuestRead(gpa, p + i, chunk)) return false;
        i += chunk;
    }
    return true;
}

static bool GvaRead64(uint64_t ttbr0, uint64_t gva, uint64_t* out) { return GvaRead(ttbr0, gva, out, 8); }
static bool GvaRead32(uint64_t ttbr0, uint64_t gva, uint32_t* out) { return GvaRead(ttbr0, gva, out, 4); }

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 1 — VBox bridge (unchanged)
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
// STAGE 2 — Map the flat guest RAM range (unchanged)
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
                (unsigned long long)hcPtr, (unsigned long long)gcStart,
                sz / (1024.0 * 1024.0 * 1024.0));
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
// STAGE 3 — Find libil2cpp.so ELF header GPA
// ═══════════════════════════════════════════════════════════════════════════════
//
// Scans for ELF64 ARM ET_DYN headers. Identifies libil2cpp.so by its unique
// PT_DYNAMIC file offset (~73 MB into the file) compared to small system SOs.
// If that heuristic is ambiguous, we still return all ARM64 ET_DYN candidates
// and let stage 3b (page table walk) disambiguate via SONAME/symbol check.

struct Elf64Hdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
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

struct Elf64Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64Dyn {
    int64_t  d_tag;
    uint64_t d_val;
};

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define DT_NULL    0
#define DT_HASH    4
#define DT_STRTAB  5
#define DT_SYMTAB  6
#define DT_STRSZ   10
#define DT_SYMENT  11
#define DT_SONAME  14
#define DT_GNU_HASH 0x6ffffef5

static const uint8_t ELF_MAGIC[4] = { 0x7f, 'E', 'L', 'F' };

// Parsed phdr summary we carry forward
struct LibInfo {
    RTGCPHYS  elf_header_gpa;
    uint64_t  load0_vaddr;      // p_vaddr of first PT_LOAD (usually 0 for PIE)
    uint64_t  load0_offset;     // p_offset of first PT_LOAD
    uint64_t  dyn_vaddr;        // p_vaddr of PT_DYNAMIC
    uint64_t  dyn_offset;       // p_offset of PT_DYNAMIC
    uint64_t  dyn_filesz;
    uint16_t  phnum;
    bool      valid;
};

static LibInfo FindLibIl2CppBase()
{
    LibInfo result = {};
    LOG("=== STAGE 3a: ELF header scan ===");
    LOG("scan range GPA 0x10000000-0x%08llX (step 4KB)",
        (unsigned long long)GUEST_RAM_BYTES);

    uint8_t page[16];
    uint32_t candidates = 0;

    for (RTGCPHYS gpa = 0x10000000ULL; gpa < GUEST_RAM_BYTES; gpa += 0x1000) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  ELF scan: GPA=%016llX", (unsigned long long)gpa);

        if (!GuestRead(gpa, page, 16)) continue;
        if (memcmp(page, ELF_MAGIC, 4) != 0) continue;
        if (page[4] != 2) continue;  // ELFCLASS64
        if (page[5] != 1) continue;  // ELFDATA2LSB

        Elf64Hdr hdr;
        if (!GuestRead(gpa, &hdr, sizeof(hdr))) continue;
        if (hdr.e_type    != 3)   continue;  // ET_DYN
        if (hdr.e_machine != 183) continue;  // EM_AARCH64
        if (hdr.e_phnum == 0 || hdr.e_phnum > 128) continue;
        if (hdr.e_phoff  == 0) continue;
        if (hdr.e_phentsize != sizeof(Elf64Phdr)) continue;

        // Parse program headers (all in first page or two — always readable)
        LibInfo li = {};
        li.elf_header_gpa = gpa;
        li.phnum          = hdr.e_phnum;
        li.load0_vaddr    = UINT64_MAX;
        bool has_dyn = false;

        for (uint16_t pi = 0; pi < hdr.e_phnum; pi++) {
            Elf64Phdr ph;
            RTGCPHYS ph_gpa = gpa + hdr.e_phoff + (uint64_t)pi * sizeof(Elf64Phdr);
            if (!GuestRead(ph_gpa, &ph, sizeof(ph))) continue;

            if (ph.p_type == PT_LOAD && ph.p_vaddr < li.load0_vaddr) {
                li.load0_vaddr  = ph.p_vaddr;
                li.load0_offset = ph.p_offset;
            }
            if (ph.p_type == PT_DYNAMIC) {
                has_dyn         = true;
                li.dyn_vaddr    = ph.p_vaddr;
                li.dyn_offset   = ph.p_offset;
                li.dyn_filesz   = ph.p_filesz;
            }
        }

        if (!has_dyn) continue;
        if (li.load0_vaddr == UINT64_MAX) li.load0_vaddr = 0;

        candidates++;
        LOG("  ARM64 ET_DYN @ GPA=%016llX  phnum=%u  dyn_offset=0x%llX (%.1f MB)",
            (unsigned long long)gpa, hdr.e_phnum,
            (unsigned long long)li.dyn_offset,
            (double)li.dyn_offset / (1024.0 * 1024.0));

        // libil2cpp.so is 81 MB; its PT_DYNAMIC lives ~73 MB into the file.
        // All system SOs have PT_DYNAMIC within the first 1 MB.
        // This is an unambiguous fingerprint — no other SO in the process is
        // remotely this large.
        if (li.dyn_offset >= 0x4000000ULL) { // > 64 MB
            LOG("  IDENTIFIED libil2cpp.so by PT_DYNAMIC offset (%.1f MB > 64 MB threshold)",
                (double)li.dyn_offset / (1024.0 * 1024.0));
            li.valid = true;
            return li;
        }
    }

    LOG("libil2cpp.so not found (%u candidates checked)", candidates);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 3b — Reverse PTE scan: find TTBR0 and load-bias GVA
// ═══════════════════════════════════════════════════════════════════════════════
//
// We know the ELF header is physically at elf_header_gpa.
// We scan all of guest RAM for an ARM64 PTE whose output address (bits[47:12])
// equals elf_header_gpa. That PTE lives inside a PTE page. We then scan for
// the PMD entry that points to that PTE page, then the PGD entry that points
// to that PMD page. The PGD page IS the TTBR0 for the process.
//
// From the PTE's position within its page we reconstruct the GVA:
//   pte_idx = (pte_location & 0xFFF) / 8    -> VA[20:12]
//   pmd_idx = (pmd_location & 0xFFF) / 8    -> VA[29:21]
//   pgd_idx = (pgd_location & 0xFFF) / 8    -> VA[38:30]
//   GVA = (pgd_idx<<30) | (pmd_idx<<21) | (pte_idx<<12)

struct PageTableInfo {
    uint64_t ttbr0;         // GPA of the PGD (== TTBR0_EL1 value)
    uint64_t load_bias_gva; // GVA corresponding to elf_header_gpa
    bool     valid;
};

static PageTableInfo FindTTBR0(RTGCPHYS elf_header_gpa)
{
    PageTableInfo result = {};
    LOG("=== STAGE 3b: reverse PTE scan for GPA=%016llX ===",
        (unsigned long long)elf_header_gpa);

    uint64_t target_oa = elf_header_gpa & ARM64_OA_MASK; // should == elf_header_gpa (page-aligned)

    // Pass 1: scan for PTEs pointing to elf_header_gpa
    // A PTE has: bits[47:12] == target_oa/0x1000, bits[1:0] == 11
    // We read 8 bytes at a time at 8-byte alignment.
    // Store the GPA of each matching PTE for the next pass.

    std::vector<RTGCPHYS> pte_locs;
    pte_locs.reserve(16);

    LOG("  pass 1: scanning for PTEs with OA=%016llX ...", (unsigned long long)target_oa);
    for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  PTE scan progress: GPA=%016llX", (unsigned long long)gpa);

        uint64_t e = 0;
        if (!GuestRead64(gpa, &e)) continue;
        if ((e & ARM64_OA_MASK) != target_oa) continue;
        if ((e & ARM64_VALID) != ARM64_VALID)  continue;
        // Sanity: upper bits should be 0 (48-bit PA) or attributes
        if ((e >> 48) != 0 && (e >> 48) < 0xFF00) continue;

        pte_locs.push_back(gpa);
        LOG("    PTE candidate @ GPA=%016llX  entry=%016llX",
            (unsigned long long)gpa, (unsigned long long)e);

        if (pte_locs.size() >= 32) break; // cap; we only need one valid chain
    }

    if (pte_locs.empty()) {
        LOG("  no PTE candidates found");
        return result;
    }

    // Pass 2: for each PTE candidate, find the PMD that points to its page,
    //         then the PGD that points to that PMD page.
    for (RTGCPHYS pte_loc : pte_locs) {
        RTGCPHYS pte_page_gpa = pte_loc & ~(RTGCPHYS)0xFFF;
        uint64_t pte_idx      = (pte_loc & 0xFFF) / 8;  // VA[20:12]

        LOG("  checking PTE @ %016llX  pte_page=%016llX  pte_idx=%llu",
            (unsigned long long)pte_loc,
            (unsigned long long)pte_page_gpa,
            (unsigned long long)pte_idx);

        // Find PMD entry pointing to pte_page_gpa
        std::vector<RTGCPHYS> pmd_locs;
        for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
            uint64_t e = 0;
            if (!GuestRead64(gpa, &e)) continue;
            if ((e & ARM64_OA_MASK) != pte_page_gpa) continue;
            if ((e & ARM64_VALID)   != ARM64_VALID)   continue;
            if ((e >> 48) != 0 && (e >> 48) < 0xFF00) continue;
            pmd_locs.push_back(gpa);
            if (pmd_locs.size() >= 8) break;
        }

        for (RTGCPHYS pmd_loc : pmd_locs) {
            RTGCPHYS pmd_page_gpa = pmd_loc & ~(RTGCPHYS)0xFFF;
            uint64_t pmd_idx      = (pmd_loc & 0xFFF) / 8;  // VA[29:21]

            // Find PGD entry pointing to pmd_page_gpa
            for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
                uint64_t e = 0;
                if (!GuestRead64(gpa, &e)) continue;
                if ((e & ARM64_OA_MASK) != pmd_page_gpa) continue;
                if ((e & ARM64_VALID)   != ARM64_VALID)   continue;
                if ((e >> 48) != 0 && (e >> 48) < 0xFF00) continue;

                RTGCPHYS pgd_page_gpa = gpa & ~(RTGCPHYS)0xFFF;
                uint64_t pgd_idx      = (gpa & 0xFFF) / 8;  // VA[38:30]

                // Reconstruct the GVA
                uint64_t load_bias = (pgd_idx << 30) | (pmd_idx << 21) | (pte_idx << 12);

                LOG("  TTBR0 candidate: pgd_page=%016llX  pgd_idx=%llu  pmd_idx=%llu  pte_idx=%llu",
                    (unsigned long long)pgd_page_gpa,
                    (unsigned long long)pgd_idx,
                    (unsigned long long)pmd_idx,
                    (unsigned long long)pte_idx);
                LOG("  reconstructed load_bias_GVA = %016llX", (unsigned long long)load_bias);

                // Sanity: GVA should be in user space (bit 63 = 0, < 0x8000000000)
                if (load_bias >= 0x8000000000ULL) continue;

                // Verify: forward walk from pgd_page_gpa should reach elf_header_gpa
                RTGCPHYS verify_gpa = 0;
                if (GvaToGpa(pgd_page_gpa, load_bias, &verify_gpa) &&
                    verify_gpa == elf_header_gpa)
                {
                    LOG("  VERIFIED: forward walk confirms TTBR0=%016llX load_bias=%016llX",
                        (unsigned long long)pgd_page_gpa,
                        (unsigned long long)load_bias);
                    result.ttbr0         = pgd_page_gpa;
                    result.load_bias_gva = load_bias;
                    result.valid         = true;
                    return result;
                }
            }
        }
    }

    LOG("  TTBR0 not found from PTE candidates");
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 4 — Read IL2CPP export RVAs via GVA page table walk
// ═══════════════════════════════════════════════════════════════════════════════
//
// Now that we have TTBR0 and load_bias_gva, we can translate any GVA in the
// process to a GPA. We read PT_DYNAMIC at its proper GVA, then walk dynsym/strtab.

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

static Il2CppExports ReadIl2CppExports(const LibInfo& lib, const PageTableInfo& pt)
{
    Il2CppExports exp = {};

    // The GVA of PT_DYNAMIC:
    //   For PIE with load0_vaddr=0: GVA = load_bias_gva + dyn_vaddr
    //   For non-PIE (load0_vaddr != 0): GVA = load_bias_gva + (dyn_vaddr - load0_vaddr)
    uint64_t dyn_gva = pt.load_bias_gva + (lib.dyn_vaddr - lib.load0_vaddr);
    LOG("PT_DYNAMIC GVA = %016llX  (load_bias=%016llX + dyn_vaddr=%016llX - load0=%016llX)",
        (unsigned long long)dyn_gva,
        (unsigned long long)pt.load_bias_gva,
        (unsigned long long)lib.dyn_vaddr,
        (unsigned long long)lib.load0_vaddr);

    // Parse PT_DYNAMIC entries
    uint64_t dt_strtab = 0, dt_symtab = 0, dt_strsz = 0, dt_syment = 0, dt_hash = 0;
    uint64_t n_dyn = lib.dyn_filesz / sizeof(Elf64Dyn);
    if (n_dyn > 512) n_dyn = 512;

    for (uint64_t di = 0; di < n_dyn; di++) {
        Elf64Dyn d;
        if (!GvaRead(pt.ttbr0, dyn_gva + di * sizeof(Elf64Dyn), &d, sizeof(d))) break;
        if (d.d_tag == DT_NULL) break;
        switch (d.d_tag) {
            case DT_STRTAB:   dt_strtab  = d.d_val; break;
            case DT_SYMTAB:   dt_symtab  = d.d_val; break;
            case DT_STRSZ:    dt_strsz   = d.d_val; break;
            case DT_SYMENT:   dt_syment  = d.d_val; break;
            case DT_HASH:     dt_hash    = d.d_val; break;
        }
    }

    LOG("DT_STRTAB=%016llX  DT_SYMTAB=%016llX  DT_STRSZ=%llu  DT_HASH=%016llX",
        (unsigned long long)dt_strtab, (unsigned long long)dt_symtab,
        (unsigned long long)dt_strsz,  (unsigned long long)dt_hash);

    if (!dt_strtab || !dt_symtab) {
        LOG("missing DT_STRTAB or DT_SYMTAB in PT_DYNAMIC");
        return exp;
    }

    // Get symbol count from DT_HASH: [0]=nbuckets, [1]=nchain (= nsyms)
    uint64_t nsyms = 0;
    if (dt_hash) {
        uint32_t nchain = 0;
        if (GvaRead32(pt.ttbr0, dt_hash + 4, &nchain) && nchain < 500000)
            nsyms = nchain;
    }
    if (!nsyms) nsyms = 200000;

    uint32_t sym_size = (dt_syment > 0 && dt_syment <= 64)
                        ? (uint32_t)dt_syment : (uint32_t)sizeof(Elf64Sym);

    LOG("scanning %llu symbols at GVA=%016llX ...", (unsigned long long)nsyms,
        (unsigned long long)dt_symtab);

    for (uint64_t si = 0; si < nsyms; si++) {
        Elf64Sym sym;
        if (!GvaRead(pt.ttbr0, dt_symtab + si * sym_size, &sym, sizeof(sym))) break;
        if (dt_strsz && sym.st_name >= dt_strsz) break;
        if (sym.st_value == 0) continue;

        std::string name = GvaReadStr(pt.ttbr0, dt_strtab + sym.st_name, 64);

        if      (name == "il2cpp_domain_get")                 exp.domain_get               = sym.st_value;
        else if (name == "il2cpp_domain_get_assemblies")      exp.domain_get_assemblies    = sym.st_value;
        else if (name == "il2cpp_class_from_name")            exp.class_from_name          = sym.st_value;
        else if (name == "il2cpp_class_get_field_from_name")  exp.class_get_field_from_name= sym.st_value;
        else if (name == "il2cpp_class_get_fields")           exp.class_get_fields         = sym.st_value;
        else if (name == "il2cpp_class_num_fields")           exp.class_num_fields         = sym.st_value;
        else if (name == "il2cpp_field_get_offset")           exp.field_get_offset         = sym.st_value;
        else if (name == "il2cpp_field_get_name")             exp.field_get_name           = sym.st_value;
        else if (name == "il2cpp_assembly_get_image")         exp.assembly_get_image       = sym.st_value;
        else if (name == "il2cpp_image_get_class")            exp.image_get_class          = sym.st_value;
        else if (name == "il2cpp_image_get_class_count")      exp.image_get_class_count    = sym.st_value;
    }

    exp.ok = exp.domain_get && exp.field_get_offset && exp.field_get_name;
    if (exp.ok)
        LOG("exports OK: domain_get=RVA+%llX  field_get_offset=RVA+%llX",
            (unsigned long long)exp.domain_get,
            (unsigned long long)exp.field_get_offset);
    else
        LOG("WARNING: exports incomplete");
    return exp;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 5 — Find field byte offsets via brute-force class scan
// ═══════════════════════════════════════════════════════════════════════════════
//
// Il2CppClass field offsets are stored in guest RAM (they're IL2CPP runtime data,
// not code). The class objects live in the Unity heap, which is in guest physical
// RAM and accessible directly via GPA reads -- no GVA translation needed here.
//
// We scan for class objects with field_count == 99 (CharacterInputController),
// then verify field names "currentLane" (index 40) and "laneIndex" (index 83).

struct FieldResult {
    uint32_t currentLane_offset;
    uint32_t laneIndex_offset;
    uint64_t class_gpa;
    bool ok;
};

static const uint32_t CLASS_OFF_NAME      = 0x10;
static const uint32_t CLASS_OFF_NAMESPACE = 0x18;
static const uint32_t CLASS_OFF_FIELDS    = 0x80;
static const uint32_t FIELD_SIZE          = 0x18;
static const uint32_t FIELD_OFF_NAME      = 0x00;
static const uint32_t FIELD_OFF_OFFSET    = 0x10;

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

static FieldResult FindLaneFields()
{
    FieldResult res = {};
    LOG("brute-force class scan for field_count=99 ...");

    for (RTGCPHYS gpa = 0x40000000ULL; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  class scan: GPA=%016llX", (unsigned long long)gpa);

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

static RTGCPHYS FindLaneGPA(const FieldResult& fields)
{
    LOG("scanning for live instances (vtable @ GPA=%016llX) ...",
        (unsigned long long)fields.class_gpa);

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

        LOG("instance @ GPA=%016llX  currentLane=%d  laneIndex=%d",
            (unsigned long long)gpa, lane_val, idx_val);
        LOG("LANE_GPA = %016llX", (unsigned long long)lane_gpa);
        return lane_gpa;
    }

    LOG("no live instances found — start a run then re-inject");
    return (RTGCPHYS)-1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE 7 — Bot read loop
// ═══════════════════════════════════════════════════════════════════════════════

static void BotLoop(RTGCPHYS lane_gpa)
{
    LOG("bot loop  LANE_GPA=%016llX", (unsigned long long)lane_gpa);
    int32_t prev = 999;
    int loop = 0;
    while (true) {
        int32_t lane = -99;
        if (GuestRead(lane_gpa, &lane, 4) && lane != prev) {
            LOG("[%6d] LANE = %d  (%s)", loop, lane,
                lane == -1 ? "LEFT" : lane == 0 ? "CENTER" : lane == 1 ? "RIGHT" : "?");
            prev = lane;
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
    if (!g_log) { OutputDebugStringA("[recon v11] fopen failed\n"); return 0; }
    LOG("v11  — autonomous IL2CPP lane resolver");

    LOG("=== STAGE 1: VBox bridge ===");
    if (!InitVBoxBridge()) goto done;
    if (!ScanForUVM())     goto done;

    LOG("=== STAGE 2: guest RAM range map ===");
    if (!InitRangeMap()) goto done;

#if DIRECT_LANE_GPA != 0
    {
        LOG("=== DIRECT_LANE_GPA bypass: GPA=%016llX ===",
            (unsigned long long)(RTGCPHYS)DIRECT_LANE_GPA);
        int32_t v = -99;
        if (GuestRead((RTGCPHYS)DIRECT_LANE_GPA, &v, 4))
            LOG("  current lane = %d", v);
        else
            LOG("  WARNING: read failed — check GPA or start a run first");
        BotLoop((RTGCPHYS)DIRECT_LANE_GPA);
        goto done;
    }
#endif

    {
        // Stage 3a — find ELF header GPA (and parse phdrs)
        LibInfo lib = FindLibIl2CppBase();
        if (!lib.valid) goto done;

        // Stage 3b — reverse PTE scan -> TTBR0 + load bias GVA
        LOG("=== STAGE 3b: page table walk ===");
        PageTableInfo pt = FindTTBR0(lib.elf_header_gpa);
        if (!pt.valid) {
            LOG("TTBR0 not found — cannot translate GVAs");
            goto done;
        }

        // Stage 4 — read exports via GVA translation
        LOG("=== STAGE 4: export RVAs ===");
        Il2CppExports exp = ReadIl2CppExports(lib, pt);
        // exp.ok is logged but we don't gate on it — field scan doesn't need it

        // Stage 5 — brute-force class scan (uses GPA reads directly)
        LOG("=== STAGE 5: field offset discovery ===");
        FieldResult fields = FindLaneFields();
        if (!fields.ok) {
            LOG("field discovery failed");
            goto done;
        }

        // Stage 6 — find live instance
        LOG("=== STAGE 6: instance scan ===");
        RTGCPHYS lane_gpa = FindLaneGPA(fields);
        if (lane_gpa == (RTGCPHYS)-1) goto done;

        // Stage 7 — bot loop
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