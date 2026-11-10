/*
 * recon.dll  v15  — two-phase TTBR0 discovery, no PT_DYNAMIC dependency
 *
 * What changed from v14:
 *   BUG FIX: TryWalk backward walk used PT_DYNAMIC accessibility as the
 *     verification signal.  PT_DYNAMIC pages are evicted post-startup (the
 *     dynamic linker reads them once, then the kernel reclaims the frames),
 *     so GvaToGpa for dyn_gva fails at every k and all walks exhausted.
 *   NEW: two-phase TTBR0 discovery.  Phase 1 (FindAllTTBR0Candidates)
 *     collects ALL (pgd, gva_res) pairs that map the SONAME page, without
 *     any backward walk or load_bias computation.  Phase 2 (ScanClass-
 *     Candidates + FindLaneFieldsMulti) scans GPA space once for class
 *     structures with field_count=99, then tries every TTBR0 candidate
 *     against them: only the game process's TTBR0 correctly translates
 *     the GVA fields pointer to a GPA whose field names read correctly.
 *   ClassCandidate struct added.  FieldResult.ttbr0 added.
 *   dyn_vaddr now logged in stage 3a for diagnosing future walk issues.
 *   Stage 4 skipped (no load_bias from two-phase path); stage 4 still
 *     runs if the classic ELF-header path ever succeeds.
 *
 * What was kept from v11->v12:
 *   - BotLoop() removed from the DLL. Bot logic lives in SubwayBot (VS project).
 *   - Named pipe server added: \\.\pipe\recon
 *   - DLL stays resident for the entire BlueStacks session. Never unload it.
 *   - DllMain ignores DLL_PROCESS_DETACH — detach path is intentionally a no-op
 *     to prevent VBox VMM state corruption on FreeLibrary.
 *
 * Protocol (all messages are newline-terminated ASCII):
 *
 *   Client -> DLL
 *   ─────────────
 *   PING\n                        heartbeat, DLL replies PONG\n
 *   SET_GPA <hex>\n               set lane GPA, DLL replies OK\n or ERR\n
 *   READ\n                        read current lane value, DLL replies LANE <n>\n
 *   HVA_BASE\n                    DLL replies HVA_BASE <hex>\n  (g_hvaBase this session)
 *   START\n                       begin streaming LANE <n>\n every 16ms until STOP
 *   STOP\n                        stop streaming
 *
 *   DLL -> Client (streaming)
 *   ─────────────────────────
 *   LANE -1\n   LEFT
 *   LANE  0\n   CENTER
 *   LANE  1\n   RIGHT
 *   LANE  ?\n   bad read (GPA stale — send new SET_GPA)
 *
 * Compile (VS x64 Native Tools prompt):
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * Inject once per BlueStacks session. Never call FreeLibrary on it.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>
#include <atomic>

// ── compile-time bypass ───────────────────────────────────────────────────────
// Set to 0 to run full self-discovery (stages 3-6).
// Set to CE_HVA - HCPtrStart for a quick bypass while self-discovery is WIP.
#define DIRECT_LANE_GPA  0x0000000000000000ULL

// ── pipe name ─────────────────────────────────────────────────────────────────
#define PIPE_NAME  "\\\\.\\pipe\\recon"

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

// Shared state between recon thread and pipe clients.
// Atomic so pipe thread can read/write without locks.
static std::atomic<uint64_t> g_laneGpa { 0 };
static std::atomic<bool>     g_streaming { false };
static std::atomic<bool>     g_bridgeReady { false };

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

static const uint64_t ARM64_OA_MASK  = 0x0000FFFFFFFFF000ULL;
static const uint64_t ARM64_VALID    = 0x3ULL;

static bool IsValidDescriptor(uint64_t e)
{
    return (e & ARM64_VALID) == ARM64_VALID &&
           (e & ARM64_OA_MASK) != 0 &&
           (e & ARM64_OA_MASK) < GUEST_RAM_BYTES;
}

static bool GvaToGpa(uint64_t ttbr0, uint64_t gva, RTGCPHYS* out_gpa)
{
    uint64_t pgd_idx = (gva >> 30) & 0x1FF;
    uint64_t pmd_idx = (gva >> 21) & 0x1FF;
    uint64_t pte_idx = (gva >> 12) & 0x1FF;
    uint64_t pg_off  = gva & 0xFFF;

    uint64_t pgd_e = 0;
    if (!GuestRead64(ttbr0 + pgd_idx * 8, &pgd_e)) return false;
    if (!IsValidDescriptor(pgd_e)) return false;
    uint64_t pmd_page = pgd_e & ARM64_OA_MASK;

    uint64_t pmd_e = 0;
    if (!GuestRead64(pmd_page + pmd_idx * 8, &pmd_e)) return false;
    if (!IsValidDescriptor(pmd_e)) return false;

    if ((pmd_e & 0x3) == 0x1) {
        uint64_t block_pa = pmd_e & 0xFFFFFFFE00000ULL;
        *out_gpa = block_pa | (gva & 0x1FFFFF);
        return *out_gpa < GUEST_RAM_BYTES;
    }
    uint64_t pte_page = pmd_e & ARM64_OA_MASK;

    uint64_t pte_e = 0;
    if (!GuestRead64(pte_page + pte_idx * 8, &pte_e)) return false;
    if (!IsValidDescriptor(pte_e)) return false;

    *out_gpa = (pte_e & ARM64_OA_MASK) | pg_off;
    return *out_gpa < GUEST_RAM_BYTES;
}

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

static bool GvaRead(uint64_t ttbr0, uint64_t gva, void* dst, size_t cb)
{
    uint8_t* p = (uint8_t*)dst;
    for (size_t i = 0; i < cb; ) {
        RTGCPHYS gpa = 0;
        if (!GvaToGpa(ttbr0, gva + i, &gpa)) return false;
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
// STAGE 3-6 stubs — same as v11, condensed here for clarity
// (ELF scan, TTBR0 walk, export read, field scan, instance scan)
// These only run when DIRECT_LANE_GPA == 0.
// ═══════════════════════════════════════════════════════════════════════════════

struct Elf64Hdr {
    uint8_t  e_ident[16]; uint16_t e_type; uint16_t e_machine;
    uint32_t e_version;   uint64_t e_entry; uint64_t e_phoff;
    uint64_t e_shoff;     uint32_t e_flags; uint16_t e_ehsize;
    uint16_t e_phentsize; uint16_t e_phnum; uint16_t e_shentsize;
    uint16_t e_shnum;     uint16_t e_shstrndx;
};
struct Elf64Phdr {
    uint32_t p_type; uint32_t p_flags; uint64_t p_offset;
    uint64_t p_vaddr; uint64_t p_paddr; uint64_t p_filesz;
    uint64_t p_memsz; uint64_t p_align;
};
struct Elf64Sym {
    uint32_t st_name; uint8_t st_info; uint8_t st_other;
    uint16_t st_shndx; uint64_t st_value; uint64_t st_size;
};
struct Elf64Dyn { int64_t d_tag; uint64_t d_val; };

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define DT_NULL    0
#define DT_HASH    4
#define DT_STRTAB  5
#define DT_SYMTAB  6
#define DT_STRSZ   10
#define DT_SYMENT  11
#define DT_SONAME  14

struct LibInfo {
    RTGCPHYS elf_header_gpa;
    uint64_t load0_vaddr, load0_offset;
    uint64_t dyn_vaddr, dyn_offset, dyn_filesz;
    uint16_t phnum;
    bool valid;
};

static LibInfo FindLibIl2CppBase()
{
    LibInfo result = {};
    LOG("=== STAGE 3a: ELF header scan ===");
    LOG("scan range GPA 0x1000000-0x%08llX (step 4KB)",
        (unsigned long long)GUEST_RAM_BYTES);

    uint8_t page[16];
    uint32_t candidates = 0;
    static const uint8_t ELF_MAGIC[4] = { 0x7f, 'E', 'L', 'F' };

    // v12: lowered scan floor to 0x1000000 to catch headers below 0x10000000
    for (RTGCPHYS gpa = 0x1000000ULL; gpa < GUEST_RAM_BYTES; gpa += 0x1000) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  ELF scan: GPA=%016llX", (unsigned long long)gpa);

        if (!GuestRead(gpa, page, 16)) continue;
        if (memcmp(page, ELF_MAGIC, 4) != 0) continue;
        if (page[4] != 2) continue;
        if (page[5] != 1) continue;

        Elf64Hdr hdr;
        if (!GuestRead(gpa, &hdr, sizeof(hdr))) continue;
        if (hdr.e_type    != 3)   continue;
        if (hdr.e_machine != 183) continue;
        if (hdr.e_phnum == 0 || hdr.e_phnum > 128) continue;
        if (hdr.e_phoff  == 0) continue;
        if (hdr.e_phentsize != sizeof(Elf64Phdr)) continue;

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
                has_dyn      = true;
                li.dyn_vaddr = ph.p_vaddr;
                li.dyn_offset= ph.p_offset;
                li.dyn_filesz= ph.p_filesz;
            }
        }

        if (!has_dyn) continue;
        if (li.load0_vaddr == UINT64_MAX) li.load0_vaddr = 0;

        candidates++;
        LOG("  ARM64 ET_DYN @ GPA=%016llX  phnum=%u  dyn_offset=0x%llX (%.1f MB)",
            (unsigned long long)gpa, hdr.e_phnum,
            (unsigned long long)li.dyn_offset,
            (double)li.dyn_offset / (1024.0 * 1024.0));

        // libil2cpp.so: PT_DYNAMIC lives >64 MB into the file — unique fingerprint.
        if (li.dyn_offset >= 0x4000000ULL) {
            LOG("  dyn_vaddr=0x%llX load0_vaddr=0x%llX dyn_offset_in_va=0x%llX",
                (unsigned long long)li.dyn_vaddr,
                (unsigned long long)li.load0_vaddr,
                (unsigned long long)(li.dyn_vaddr - li.load0_vaddr));
            LOG("  IDENTIFIED libil2cpp.so (dyn_offset %.1f MB > 64 MB threshold)",
                (double)li.dyn_offset / (1024.0 * 1024.0));
            li.valid = true;
            return li;
        }
    }

    LOG("libil2cpp.so not found (%u candidates checked)", candidates);
    return result;
}

struct PageTableInfo { uint64_t ttbr0, load_bias_gva; bool valid; };

static PageTableInfo FindTTBR0(RTGCPHYS elf_header_gpa)
{
    PageTableInfo result = {};
    LOG("=== STAGE 3b: reverse PTE scan for GPA=%016llX ===",
        (unsigned long long)elf_header_gpa);

    uint64_t target_oa = elf_header_gpa & ARM64_OA_MASK;
    std::vector<RTGCPHYS> pte_locs;
    pte_locs.reserve(16);

    LOG("  pass 1: scanning for PTEs with OA=%016llX ...", (unsigned long long)target_oa);
    for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  PTE scan progress: GPA=%016llX", (unsigned long long)gpa);
        uint64_t e = 0;
        if (!GuestRead64(gpa, &e)) continue;
        if ((e & ARM64_OA_MASK) != target_oa) continue;
        if (!IsValidDescriptor(e)) continue;
        pte_locs.push_back(gpa);
        LOG("    PTE candidate @ GPA=%016llX  entry=%016llX",
            (unsigned long long)gpa, (unsigned long long)e);
        if (pte_locs.size() >= 32) break;
    }

    if (pte_locs.empty()) { LOG("  no PTE candidates found"); return result; }

    for (RTGCPHYS pte_loc : pte_locs) {
        RTGCPHYS pte_page_gpa = pte_loc & ~(RTGCPHYS)0xFFF;
        uint64_t pte_idx      = (pte_loc & 0xFFF) / 8;

        std::vector<RTGCPHYS> pmd_locs;
        for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
            uint64_t e = 0;
            if (!GuestRead64(gpa, &e)) continue;
            if ((e & ARM64_OA_MASK) != pte_page_gpa) continue;
            if (!IsValidDescriptor(e)) continue;
            pmd_locs.push_back(gpa);
            if (pmd_locs.size() >= 8) break;
        }

        for (RTGCPHYS pmd_loc : pmd_locs) {
            RTGCPHYS pmd_page_gpa = pmd_loc & ~(RTGCPHYS)0xFFF;
            uint64_t pmd_idx      = (pmd_loc & 0xFFF) / 8;

            for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
                uint64_t e = 0;
                if (!GuestRead64(gpa, &e)) continue;
                if ((e & ARM64_OA_MASK) != pmd_page_gpa) continue;
                if (!IsValidDescriptor(e)) continue;

                RTGCPHYS pgd_page_gpa = gpa & ~(RTGCPHYS)0xFFF;
                uint64_t pgd_idx      = (gpa & 0xFFF) / 8;
                uint64_t load_bias    = (pgd_idx << 30) | (pmd_idx << 21) | (pte_idx << 12);

                if (load_bias >= 0x8000000000ULL) continue;

                RTGCPHYS verify_gpa = 0;
                if (GvaToGpa(pgd_page_gpa, load_bias, &verify_gpa) &&
                    verify_gpa == elf_header_gpa)
                {
                    LOG("  VERIFIED: TTBR0=%016llX load_bias=%016llX",
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

    LOG("  TTBR0 not found");
    return result;
}


// ── FindSonamePageGPA ─────────────────────────────────────────────────────────────────────────────────
// ELF header page of libil2cpp.so is evicted after mmap — no live PTEs
// point to it.  ".dynstr" in .rodata is always resident.  Scan for the
// null-terminated SONAME "libil2cpp.so" and return its page-aligned GPA,
// or (RTGCPHYS)-1 on failure.

static RTGCPHYS FindSonamePageGPA()
{
    static const char SONAME[] = "libil2cpp.so";
    static const size_t SL     = sizeof(SONAME);
    LOG("=== stage 3b-pre: scanning for SONAME \"libil2cpp.so\" ===");
    uint8_t pg[4096];
    for (RTGCPHYS gpa = 0x4000000ULL; gpa < GUEST_RAM_BYTES; gpa += 0x1000) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  SONAME scan: GPA=%016llX", (unsigned long long)gpa);
        if (!GuestRead(gpa, pg, sizeof(pg))) continue;
        for (size_t off = 0; off + SL <= sizeof(pg); off++) {
            if (pg[off] != 'l') continue;
            if (memcmp(pg + off, SONAME, SL) != 0) continue;
            if (off > 0 && pg[off - 1] != '\0') continue;
            LOG("  found at GPA=%016llX+0x%03zx", (unsigned long long)gpa, off);
            return gpa;
        }
    }
    LOG("  SONAME string not found in guest RAM");
    return (RTGCPHYS)-1ULL;
}


// ── FindAllTTBR0Candidates ─────────────────────────────────────────────────────────────────────────
//
// Replaces FindTTBR0_Resident's TryWalk approach.  TryWalk verified via
// PT_DYNAMIC accessibility; those pages are evicted post-startup (dynamic
// linker reads them once, kernel reclaims the frames) so the walk always
// exhausted.
//
// This function collects ALL (pgd, gva_res) pairs that map the SONAME page
// without any backward walk.  load_bias_gva is left at 0.  The correct
// TTBR0 (game process) is identified later in FindLaneFieldsMulti, which
// tries each candidate against pre-scanned class structure candidates:
// only the game process's TTBR0 correctly translates the GVA fields pointer
// to a readable field-name GPA.
//
// Up to MAX_CANDIDATES unique TTBR0 values are returned (deduplicated by
// pgd address).

static std::vector<PageTableInfo>
FindAllTTBR0Candidates(RTGCPHYS resident_gpa, const LibInfo& lib)
{
    std::vector<PageTableInfo> results;
    static const size_t MAX_CANDIDATES = 64;

    if (resident_gpa == (RTGCPHYS)-1ULL) {
        LOG("FindAllTTBR0Candidates: no resident page");
        return results;
    }

    uint64_t target_oa     = resident_gpa & ARM64_OA_MASK;
    uint64_t target_oa_2mb = resident_gpa & 0x0000FFFFFFE00000ULL;
    uint64_t page_in_block = target_oa & 0x0000000001FF000ULL;

    LOG("=== stage 3b-candidates: leaf scan for GPA=%016llX ===",
        (unsigned long long)resident_gpa);

    // ---- pass 1: 4KB PTEs and 2MB PMD blocks --------------------------------
    struct LeafEntry { RTGCPHYS loc; bool is_block; };
    std::vector<LeafEntry> leaves;
    leaves.reserve(32);
    for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  leaf scan: GPA=%016llX", (unsigned long long)gpa);
        uint64_t e = 0;
        if (!GuestRead64(gpa, &e)) continue;
        uint8_t type = (uint8_t)(e & 0x3);
        if (type == 0x3) {
            if (!IsValidDescriptor(e)) continue;
            if ((e & ARM64_OA_MASK) == target_oa) leaves.push_back({gpa, false});
        } else if (type == 0x1) {
            uint64_t oa2 = e & 0x0000FFFFFFE00000ULL;
            if (oa2 == target_oa_2mb && oa2 > 0 && oa2 < GUEST_RAM_BYTES)
                leaves.push_back({gpa, true});
        }
        if (leaves.size() >= 32) break;
    }
    if (leaves.empty()) { LOG("  no leaf entries found"); return results; }
    LOG("  %zu leaf entries found", leaves.size());

    // ---- passes 2 & 3: walk leaf → PGD, collect unique TTBR0s ---------------
    for (const auto& leaf : leaves) {
        if (results.size() >= MAX_CANDIDATES) break;
        RTGCPHYS lp = leaf.loc & ~(RTGCPHYS)0xFFF;
        uint64_t li = (leaf.loc & 0xFFF) / 8;

        if (!leaf.is_block) {
            // 4KB path: PTE page -> PMD (table) -> PGD
            std::vector<RTGCPHYS> pmds;
            for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
                uint64_t e = 0;
                if (!GuestRead64(gpa, &e)) continue;
                if (!IsValidDescriptor(e)) continue;
                if ((e & ARM64_OA_MASK) != lp) continue;
                pmds.push_back(gpa);
                if (pmds.size() >= 8) break;
            }
            for (RTGCPHYS pm : pmds) {
                if (results.size() >= MAX_CANDIDATES) break;
                RTGCPHYS pp = pm & ~(RTGCPHYS)0xFFF;
                uint64_t pi = (pm & 0xFFF) / 8;
                for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
                    if (results.size() >= MAX_CANDIDATES) break;
                    uint64_t e = 0;
                    if (!GuestRead64(gpa, &e)) continue;
                    if (!IsValidDescriptor(e)) continue;
                    if ((e & ARM64_OA_MASK) != pp) continue;
                    RTGCPHYS pgd = gpa & ~(RTGCPHYS)0xFFF;
                    uint64_t gi  = (gpa & 0xFFF) / 8;
                    uint64_t gva = (gi << 30) | (pi << 21) | (li << 12);
                    if (gva >= 0x8000000000ULL) continue;
                    // Sanity: GvaToGpa should map gva -> target_oa
                    RTGCPHYS chk = 0;
                    if (!GvaToGpa(pgd, gva, &chk) || chk != target_oa) continue;
                    bool dup = false;
                    for (const auto& r : results) if (r.ttbr0 == pgd) { dup=true; break; }
                    if (dup) continue;
                    LOG("  4KB cand: pgd=%016llX gva=%016llX",
                        (unsigned long long)pgd, (unsigned long long)gva);
                    results.push_back({pgd, 0, true});
                }
            }
        } else {
            // 2MB path: PMD block IS leaf -> PGD (one level up)
            for (RTGCPHYS gpa = 0; gpa < GUEST_RAM_BYTES; gpa += 8) {
                if (results.size() >= MAX_CANDIDATES) break;
                uint64_t e = 0;
                if (!GuestRead64(gpa, &e)) continue;
                if (!IsValidDescriptor(e)) continue;
                if ((e & ARM64_OA_MASK) != lp) continue;
                RTGCPHYS pgd = gpa & ~(RTGCPHYS)0xFFF;
                uint64_t gi  = (gpa & 0xFFF) / 8;
                uint64_t gva = (gi << 30) | (li << 21) | page_in_block;
                if (gva >= 0x8000000000ULL) continue;
                RTGCPHYS chk = 0;
                if (!GvaToGpa(pgd, gva, &chk) || chk != target_oa) continue;
                bool dup = false;
                for (const auto& r : results) if (r.ttbr0 == pgd) { dup=true; break; }
                if (dup) continue;
                LOG("  2MB cand: pgd=%016llX gva=%016llX",
                    (unsigned long long)pgd, (unsigned long long)gva);
                results.push_back({pgd, 0, true});
            }
        }
    }
    LOG("  %zu unique TTBR0 candidates collected", results.size());
    return results;
}


struct Il2CppExports {
    uint64_t domain_get, domain_get_assemblies, class_from_name;
    uint64_t class_get_field_from_name, class_get_fields, class_num_fields;
    uint64_t field_get_offset, field_get_name;
    uint64_t assembly_get_image, image_get_class, image_get_class_count;
    bool ok;
};

static Il2CppExports ReadIl2CppExports(const LibInfo& lib, const PageTableInfo& pt)
{
    Il2CppExports exp = {};
    uint64_t dyn_gva = pt.load_bias_gva + (lib.dyn_vaddr - lib.load0_vaddr);
    LOG("PT_DYNAMIC GVA = %016llX", (unsigned long long)dyn_gva);

    uint64_t dt_strtab = 0, dt_symtab = 0, dt_strsz = 0, dt_syment = 0, dt_hash = 0;
    uint64_t n_dyn = lib.dyn_filesz / sizeof(Elf64Dyn);
    if (n_dyn > 512) n_dyn = 512;

    for (uint64_t di = 0; di < n_dyn; di++) {
        Elf64Dyn d;
        if (!GvaRead(pt.ttbr0, dyn_gva + di * sizeof(Elf64Dyn), &d, sizeof(d))) break;
        if (d.d_tag == DT_NULL) break;
        switch (d.d_tag) {
            case DT_STRTAB:  dt_strtab  = d.d_val; break;
            case DT_SYMTAB:  dt_symtab  = d.d_val; break;
            case DT_STRSZ:   dt_strsz   = d.d_val; break;
            case DT_SYMENT:  dt_syment  = d.d_val; break;
            case DT_HASH:    dt_hash    = d.d_val; break;
        }
    }

    if (!dt_strtab || !dt_symtab) {
        LOG("missing DT_STRTAB or DT_SYMTAB");
        return exp;
    }

    uint64_t nsyms = 0;
    if (dt_hash) {
        uint32_t nchain = 0;
        if (GvaRead32(pt.ttbr0, dt_hash + 4, &nchain) && nchain < 500000)
            nsyms = nchain;
    }
    if (!nsyms) nsyms = 200000;

    uint32_t sym_size = (dt_syment > 0 && dt_syment <= 64)
                        ? (uint32_t)dt_syment : (uint32_t)sizeof(Elf64Sym);

    for (uint64_t si = 0; si < nsyms; si++) {
        Elf64Sym sym;
        if (!GvaRead(pt.ttbr0, dt_symtab + si * sym_size, &sym, sizeof(sym))) break;
        if (dt_strsz && sym.st_name >= dt_strsz) break;
        if (sym.st_value == 0) continue;
        std::string name = GvaReadStr(pt.ttbr0, dt_strtab + sym.st_name, 64);
        if      (name == "il2cpp_domain_get")                exp.domain_get              = sym.st_value;
        else if (name == "il2cpp_domain_get_assemblies")     exp.domain_get_assemblies   = sym.st_value;
        else if (name == "il2cpp_class_from_name")           exp.class_from_name         = sym.st_value;
        else if (name == "il2cpp_class_get_field_from_name") exp.class_get_field_from_name=sym.st_value;
        else if (name == "il2cpp_class_get_fields")          exp.class_get_fields        = sym.st_value;
        else if (name == "il2cpp_class_num_fields")          exp.class_num_fields        = sym.st_value;
        else if (name == "il2cpp_field_get_offset")          exp.field_get_offset        = sym.st_value;
        else if (name == "il2cpp_field_get_name")            exp.field_get_name          = sym.st_value;
        else if (name == "il2cpp_assembly_get_image")        exp.assembly_get_image      = sym.st_value;
        else if (name == "il2cpp_image_get_class")           exp.image_get_class         = sym.st_value;
        else if (name == "il2cpp_image_get_class_count")     exp.image_get_class_count   = sym.st_value;
    }

    exp.ok = exp.domain_get && exp.field_get_offset && exp.field_get_name;
    LOG("exports %s", exp.ok ? "OK" : "incomplete");
    return exp;
}

// GPA + GVA-of-fields-array for one class structure found during scan
struct ClassCandidate { RTGCPHYS gpa; uint64_t fields_gva; };

struct FieldResult {
    uint32_t currentLane_offset, laneIndex_offset;
    RTGCPHYS class_gpa;
    RTGCPHYS ttbr0;    // winning TTBR0, or 0 if not via page table
    bool ok;
};

static const uint32_t CLASS_OFF_NAME      = 0x10;
static const uint32_t CLASS_OFF_NAMESPACE = 0x18;
static const uint32_t CLASS_OFF_FIELDS    = 0x80;
static const uint32_t FIELD_SIZE          = 0x18;
static const uint32_t FIELD_OFF_NAME      = 0x00;
static const uint32_t FIELD_OFF_OFFSET    = 0x10;

static bool TryReadFieldOffset(RTGCPHYS fields_gpa, uint32_t field_idx,
                                const char* expected_name, uint32_t* out_offset,
                                RTGCPHYS ttbr0 = 0)
{
    RTGCPHYS fgpa = fields_gpa + (uint64_t)field_idx * FIELD_SIZE;
    uint64_t name_gva = 0;
    if (!GuestRead64(fgpa + FIELD_OFF_NAME, &name_gva)) return false;
    if (!name_gva) return false;
    std::string fname;
    if (ttbr0 != 0 && name_gva >= GUEST_RAM_BYTES)
        fname = GvaReadStr(ttbr0, name_gva, 64);
    else if (name_gva < GUEST_RAM_BYTES)
        fname = GuestReadStr((RTGCPHYS)name_gva, 64);
    else
        return false;
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

// ScanClassCandidates: single page-granularity scan of guest RAM.
// Collects (gpa, fields_gva) pairs where any known field-count offset holds 99.
// Called once; results are reused by FindLaneFieldsMulti across all TTBR0 candidates.
static std::vector<ClassCandidate> ScanClassCandidates()
{
    std::vector<ClassCandidate> results;
    static const uint32_t fc_offs[] = { 0xBC, 0xB8, 0xC0, 0xC4, 0x88, 0x90 };
    static const uint32_t MAX_OFF = 0x1000 - 0x100;
    uint8_t page[4096];
    LOG("=== STAGE 5a: class candidate scan ===");
    for (RTGCPHYS pgpa = 0x40000000ULL; pgpa < GUEST_RAM_BYTES; pgpa += 0x1000) {
        if ((pgpa & 0x0FFFFFFF) == 0)
            LOG("  candidate scan: GPA=%016llX", (unsigned long long)pgpa);
        if (!GuestRead(pgpa, page, sizeof(page))) continue;
        for (uint32_t off = 0; off < MAX_OFF; off += 8) {
            bool fc_ok = false;
            for (uint32_t fco : fc_offs) {
                uint32_t v; memcpy(&v, page + off + fco, 4);
                if ((v & 0xFFFF) == 99) { fc_ok = true; break; }
            }
            if (!fc_ok) continue;
            uint64_t fields_gva = 0;
            GuestRead64(pgpa + off + CLASS_OFF_FIELDS, &fields_gva);
            if (!fields_gva) continue;
            results.push_back({pgpa + off, fields_gva});
            if (results.size() >= 500) goto scan_done;
        }
    }
scan_done:
    LOG("  %zu class candidates with field_count=99", results.size());
    return results;
}

// FindLaneFieldsMulti: for each TTBR0 candidate, try to match one of the
// pre-scanned class candidates.  Only the game process's TTBR0 correctly
// translates the GVA fields pointer to a GPA whose field names read back as
// "currentLane" and "laneIndex".  Runs in microseconds after ScanClassCandidates.
static FieldResult FindLaneFieldsMulti(
    const std::vector<ClassCandidate>& class_cands,
    const std::vector<PageTableInfo>&  ttbr0_list)
{
    LOG("=== STAGE 5b: TTBR0 x class matching (%zu ttbrs, %zu candidates) ===",
        ttbr0_list.size(), class_cands.size());
    for (const auto& pt : ttbr0_list) {
        for (const auto& cand : class_cands) {
            RTGCPHYS fields_ptr = 0;
            if (pt.ttbr0 != 0 && cand.fields_gva >= GUEST_RAM_BYTES) {
                if (!GvaToGpa(pt.ttbr0, cand.fields_gva, &fields_ptr)) continue;
            } else if (cand.fields_gva < GUEST_RAM_BYTES && !(cand.fields_gva & 7)) {
                fields_ptr = (RTGCPHYS)cand.fields_gva;
            } else {
                continue;
            }
            uint32_t off40 = 0, off83 = 0;
            if (!TryReadFieldOffset(fields_ptr, 40, "currentLane", &off40, pt.ttbr0)) continue;
            if (!TryReadFieldOffset(fields_ptr, 83, "laneIndex",   &off83, pt.ttbr0)) continue;
            uint64_t name_gva = 0; GuestRead64(cand.gpa + CLASS_OFF_NAME, &name_gva);
            std::string cls_name;
            if (pt.ttbr0 != 0 && name_gva >= GUEST_RAM_BYTES)
                cls_name = GvaReadStr(pt.ttbr0, name_gva, 128);
            else if (name_gva && name_gva < GUEST_RAM_BYTES)
                cls_name = GuestReadStr((RTGCPHYS)name_gva, 128);
            else
                cls_name = "<unknown>";
            LOG("FOUND [ttbr0=%016llX] class \"%s\" @ GPA=%016llX "
                "currentLane=+%u  laneIndex=+%u",
                (unsigned long long)pt.ttbr0, cls_name.c_str(),
                (unsigned long long)cand.gpa, off40, off83);
            FieldResult res;
            res.ok = true;
            res.currentLane_offset = off40;
            res.laneIndex_offset   = off83;
            res.class_gpa          = cand.gpa;
            res.ttbr0              = pt.ttbr0;
            return res;
        }
    }
    LOG("  no TTBR0 matched any class candidate");
    return {};
}

// FindLaneFields: single-TTBR0 fallback (kept for direct use if needed)
static FieldResult FindLaneFields(RTGCPHYS ttbr0 = 0)
{
    FieldResult res = {};
    LOG("brute-force class scan for field_count=99 (ttbr0=%016llX) ...",
        (unsigned long long)ttbr0);
    static const uint32_t fc_offs[] = { 0xBC, 0xB8, 0xC0, 0xC4, 0x88, 0x90 };
    static const uint32_t MAX_OFF = 0x1000 - 0x100;
    uint8_t page[4096];
    for (RTGCPHYS pgpa = 0x40000000ULL; pgpa < GUEST_RAM_BYTES; pgpa += 0x1000) {
        if ((pgpa & 0x0FFFFFFF) == 0)
            LOG("  class scan: GPA=%016llX", (unsigned long long)pgpa);
        if (!GuestRead(pgpa, page, sizeof(page))) continue;
        for (uint32_t off = 0; off < MAX_OFF; off += 8) {
            bool fc_ok = false;
            for (uint32_t fco : fc_offs) {
                uint32_t v; memcpy(&v, page + off + fco, 4);
                if ((v & 0xFFFF) == 99) { fc_ok = true; break; }
            }
            if (!fc_ok) continue;
            RTGCPHYS gpa = pgpa + off;
            uint64_t fields_gva = 0;
            if (!GuestRead64(gpa + CLASS_OFF_FIELDS, &fields_gva)) continue;
            if (!fields_gva) continue;
            RTGCPHYS fields_ptr = 0;
            if (ttbr0 != 0 && fields_gva >= GUEST_RAM_BYTES) {
                if (!GvaToGpa(ttbr0, fields_gva, &fields_ptr)) continue;
            } else if (fields_gva < GUEST_RAM_BYTES && !(fields_gva & 7)) {
                fields_ptr = (RTGCPHYS)fields_gva;
            } else { continue; }
            uint32_t off40 = 0, off83 = 0;
            if (!TryReadFieldOffset(fields_ptr, 40, "currentLane", &off40, ttbr0)) continue;
            if (!TryReadFieldOffset(fields_ptr, 83, "laneIndex",   &off83, ttbr0)) continue;
            uint64_t name_gva = 0; GuestRead64(gpa + CLASS_OFF_NAME, &name_gva);
            std::string cls_name;
            if (ttbr0 != 0 && name_gva >= GUEST_RAM_BYTES)
                cls_name = GvaReadStr(ttbr0, name_gva, 128);
            else if (name_gva && name_gva < GUEST_RAM_BYTES)
                cls_name = GuestReadStr((RTGCPHYS)name_gva, 128);
            else cls_name = "<unknown>";
            LOG("FOUND class \"%s\" @ GPA=%016llX  currentLane=+%u  laneIndex=+%u",
                cls_name.c_str(), (unsigned long long)gpa, off40, off83);
            res.ok = true; res.currentLane_offset = off40;
            res.laneIndex_offset = off83; res.class_gpa = gpa; res.ttbr0 = ttbr0;
            return res;
        }
    }
    LOG("class not found");
    return res;
}

static RTGCPHYS FindLaneGPA(const FieldResult& fields, RTGCPHYS ttbr0 = 0)
{
    LOG("scanning for live instances (ttbr0=%016llX) ...", (unsigned long long)ttbr0);
    for (RTGCPHYS gpa = 0x40000000ULL; gpa < GUEST_RAM_BYTES; gpa += 8) {
        if ((gpa & 0x0FFFFFFF) == 0)
            LOG("  instance scan: GPA=%016llX", (unsigned long long)gpa);
        uint64_t klass_gva = 0;
        if (!GuestRead64(gpa, &klass_gva)) continue;
        if (!klass_gva) continue;
        if (ttbr0 != 0) {
            RTGCPHYS klass_gpa = 0;
            if (!GvaToGpa(ttbr0, klass_gva, &klass_gpa)) continue;
            if (klass_gpa != fields.class_gpa) continue;
        } else {
            if (klass_gva != (uint64_t)fields.class_gpa) continue;
        }
        RTGCPHYS lane_gpa = gpa + fields.currentLane_offset;
        int32_t lane_val = 0;
        if (!GuestRead(lane_gpa, &lane_val, 4)) continue;
        if (lane_val < -1 || lane_val > 1) continue;
        int32_t idx_val = 0;
        if (!GuestRead(gpa + fields.laneIndex_offset, &idx_val, 4)) continue;
        if (idx_val < -1 || idx_val > 1) continue;
        LOG("instance @ GPA=%016llX  currentLane=%d", (unsigned long long)gpa, lane_val);
        LOG("LANE_GPA = %016llX", (unsigned long long)lane_gpa);
        return lane_gpa;
    }
    LOG("no live instances found — start a run then send SET_GPA via pipe");
    return (RTGCPHYS)-1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pipe helpers
// ═══════════════════════════════════════════════════════════════════════════════

// Write a full line to the pipe. Returns false if the pipe broke.
static bool PipeSend(HANDLE pipe, const char* msg)
{
    DWORD written = 0;
    return WriteFile(pipe, msg, (DWORD)strlen(msg), &written, nullptr) == TRUE;
}

// Read one newline-terminated line from the pipe into buf (null-terminated).
// Returns false on disconnect or error.
static bool PipeReadLine(HANDLE pipe, char* buf, DWORD bufsz)
{
    DWORD i = 0;
    while (i < bufsz - 1) {
        char c = 0;
        DWORD got = 0;
        if (!ReadFile(pipe, &c, 1, &got, nullptr) || got == 0) return false;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = 0;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pipe client handler — one thread per connected client
// ═══════════════════════════════════════════════════════════════════════════════

static DWORD WINAPI PipeClientThread(LPVOID arg)
{
    HANDLE pipe = (HANDLE)arg;
    char buf[256];

    // Send a banner so the client knows the bridge state immediately
    if (!g_bridgeReady.load()) {
        PipeSend(pipe, "STATUS BRIDGE_NOT_READY\n");
    } else {
        char banner[128];
        snprintf(banner, sizeof(banner),
                 "STATUS READY HVA_BASE %016llX\n",
                 (unsigned long long)g_hvaBase);
        PipeSend(pipe, banner);
    }

    while (true) {
        if (!PipeReadLine(pipe, buf, sizeof(buf))) break;

        if (strcmp(buf, "PING") == 0) {
            if (!PipeSend(pipe, "PONG\n")) break;
        }
        else if (strcmp(buf, "HVA_BASE") == 0) {
            char resp[64];
            snprintf(resp, sizeof(resp), "HVA_BASE %016llX\n",
                     (unsigned long long)g_hvaBase);
            if (!PipeSend(pipe, resp)) break;
        }
        else if (strncmp(buf, "SET_GPA ", 8) == 0) {
            uint64_t gpa = 0;
            if (sscanf_s(buf + 8, "%llx", &gpa) == 1 && gpa < GUEST_RAM_BYTES) {
                g_laneGpa.store(gpa);
                LOG("pipe: SET_GPA %016llX", (unsigned long long)gpa);
                if (!PipeSend(pipe, "OK\n")) break;
            } else {
                if (!PipeSend(pipe, "ERR bad GPA\n")) break;
            }
        }
        else if (strcmp(buf, "READ") == 0) {
            RTGCPHYS gpa = (RTGCPHYS)g_laneGpa.load();
            int32_t val = -99;
            char resp[32];
            if (gpa == 0) {
                snprintf(resp, sizeof(resp), "ERR no GPA set\n");
            } else if (GuestRead(gpa, &val, 4) && val >= -1 && val <= 1) {
                snprintf(resp, sizeof(resp), "LANE %d\n", val);
            } else {
                snprintf(resp, sizeof(resp), "LANE ?\n");
            }
            if (!PipeSend(pipe, resp)) break;
        }
        else if (strcmp(buf, "START") == 0) {
            g_streaming.store(true);
            if (!PipeSend(pipe, "OK\n")) break;

            // Stream until STOP or disconnect
            int32_t prev = 999;
            while (g_streaming.load()) {
                RTGCPHYS gpa = (RTGCPHYS)g_laneGpa.load();
                int32_t val = -99;
                char resp[32];

                if (gpa != 0 && GuestRead(gpa, &val, 4) && val >= -1 && val <= 1) {
                    if (val != prev) {
                        snprintf(resp, sizeof(resp), "LANE %d\n", val);
                        if (!PipeSend(pipe, resp)) goto client_done;
                        prev = val;
                    }
                } else if (gpa != 0) {
                    // Bad read — notify once
                    if (prev != -99) {
                        if (!PipeSend(pipe, "LANE ?\n")) goto client_done;
                        prev = -99;
                    }
                }

                // Non-blocking command check while streaming.
                // Handles STOP, SET_GPA, PING, READ — anything the client sends mid-stream.
                DWORD avail = 0;
                if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                    char cmd[256] = {};
                    if (!PipeReadLine(pipe, cmd, sizeof(cmd))) goto client_done;

                    if (strcmp(cmd, "STOP") == 0) {
                        g_streaming.store(false);
                        PipeSend(pipe, "OK\n");
                        break;
                    }
                    else if (strncmp(cmd, "SET_GPA ", 8) == 0) {
                        uint64_t newgpa = 0;
                        if (sscanf_s(cmd + 8, "%llx", &newgpa) == 1 && newgpa < GUEST_RAM_BYTES) {
                            g_laneGpa.store(newgpa);
                            prev = 999; // force immediate emit on next tick
                            LOG("pipe: SET_GPA %016llX (mid-stream)", (unsigned long long)newgpa);
                            if (!PipeSend(pipe, "OK\n")) goto client_done;
                        } else {
                            if (!PipeSend(pipe, "ERR bad GPA\n")) goto client_done;
                        }
                    }
                    else if (strcmp(cmd, "PING") == 0) {
                        if (!PipeSend(pipe, "PONG\n")) goto client_done;
                    }
                    else if (strcmp(cmd, "READ") == 0) {
                        RTGCPHYS rgpa = (RTGCPHYS)g_laneGpa.load();
                        int32_t rval = -99;
                        char rresp[32];
                        if (rgpa == 0) {
                            snprintf(rresp, sizeof(rresp), "ERR no GPA set\n");
                        } else if (GuestRead(rgpa, &rval, 4) && rval >= -1 && rval <= 1) {
                            snprintf(rresp, sizeof(rresp), "LANE %d\n", rval);
                        } else {
                            snprintf(rresp, sizeof(rresp), "LANE ?\n");
                        }
                        if (!PipeSend(pipe, rresp)) goto client_done;
                    }
                    // unknown mid-stream command: silently ignore to keep stream alive
                }

                Sleep(16);
            }
        }
        else if (strcmp(buf, "STOP") == 0) {
            g_streaming.store(false);
            if (!PipeSend(pipe, "OK\n")) break;
        }
        else {
            char resp[128];
            snprintf(resp, sizeof(resp), "ERR unknown command: %s\n", buf);
            if (!PipeSend(pipe, resp)) break;
        }
    }

client_done:
    LOG("pipe client disconnected");
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pipe server — accepts connections forever, spawns a thread per client
// ═══════════════════════════════════════════════════════════════════════════════

static DWORD WINAPI PipeServerThread(LPVOID)
{
    LOG("pipe server started: " PIPE_NAME);
    while (true) {
        HANDLE pipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096,
            0, nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            LOG("CreateNamedPipe failed: %lu", GetLastError());
            Sleep(1000);
            continue;
        }

        // Block until a client connects
        if (!ConnectNamedPipe(pipe, nullptr)) {
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(pipe);
                continue;
            }
        }

        LOG("pipe client connected");
        CreateThread(nullptr, 0, PipeClientThread, (LPVOID)pipe, 0, nullptr);
        // Loop immediately to accept the next client
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main recon thread — runs once, sets up bridge, then pipe server takes over
// ═══════════════════════════════════════════════════════════════════════════════

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);
    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon v12] fopen failed\n"); return 0; }
    LOG("v12  — persistent pipe server");

    // Start pipe server immediately — clients can connect even before bridge is ready
    // and will receive STATUS BRIDGE_NOT_READY until it is.
    CreateThread(nullptr, 0, PipeServerThread, nullptr, 0, nullptr);

    LOG("=== STAGE 1: VBox bridge ===");
    if (!InitVBoxBridge()) goto done;
    if (!ScanForUVM())     goto done;

    LOG("=== STAGE 2: guest RAM range map ===");
    if (!InitRangeMap()) goto done;

    g_bridgeReady.store(true);
    LOG("bridge ready — HVA_BASE=%016llX", (unsigned long long)g_hvaBase);

#if DIRECT_LANE_GPA != 0
    {
        RTGCPHYS bypass_gpa = (RTGCPHYS)DIRECT_LANE_GPA;
        g_laneGpa.store(bypass_gpa);
        int32_t v = -99;
        if (GuestRead(bypass_gpa, &v, 4) && v >= -1 && v <= 1)
            LOG("DIRECT_LANE_GPA bypass: GPA=%016llX  lane=%d", (unsigned long long)bypass_gpa, v);
        else
            LOG("DIRECT_LANE_GPA bypass: GPA=%016llX  WARNING: bad read (start a run first)",
                (unsigned long long)bypass_gpa);
        // Bot loop is gone — SubwayBot drives from here via pipe.
        goto done;
    }
#endif

    // Full self-discovery path
    {
        LibInfo lib = FindLibIl2CppBase();
        if (!lib.valid) goto done;

        // ---- stage 3b: collect TTBR0 candidates ----------------------------
        // Classic path (ELF header page, usually evicted): may give us
        // load_bias_gva, enabling stage 4.  SONAME path collects all candidate
        // TTBR0s without a backward walk -- game process identified in stage 5b.
        LOG("=== STAGE 3b: TTBR0 candidates ===");
        std::vector<PageTableInfo> ttbr0_list;
        {
            PageTableInfo pt_classic = FindTTBR0(lib.elf_header_gpa);
            if (pt_classic.valid) {
                LOG("  classic path: TTBR0=%016llX load_bias=%016llX",
                    (unsigned long long)pt_classic.ttbr0,
                    (unsigned long long)pt_classic.load_bias_gva);
                ttbr0_list.push_back(pt_classic);
            }
        }
        {
            RTGCPHYS soname_gpa = FindSonamePageGPA();
            auto soname_ttbrs   = FindAllTTBR0Candidates(soname_gpa, lib);
            for (auto& t : soname_ttbrs) ttbr0_list.push_back(t);
        }
        LOG("  total TTBR0 candidates: %zu", ttbr0_list.size());

        // ---- stage 4: exports (only when load_bias is known) ----------------
        for (const auto& pt : ttbr0_list) {
            if (pt.load_bias_gva != 0) {
                LOG("=== STAGE 4: export RVAs ===");
                ReadIl2CppExports(lib, pt);
                break;
            }
        }

        // ---- stage 5: two-phase class discovery ----------------------------
        auto class_cands = ScanClassCandidates();

        FieldResult fields = FindLaneFieldsMulti(class_cands, ttbr0_list);
        if (!fields.ok) { LOG("field discovery failed"); goto done; }

        LOG("=== STAGE 6: instance scan ===");
        RTGCPHYS lane_gpa = FindLaneGPA(fields, fields.ttbr0);
        if (lane_gpa != (RTGCPHYS)-1) {
            g_laneGpa.store(lane_gpa);
            LOG("auto-discovered LANE_GPA=%016llX — pipe server is streaming",
                (unsigned long long)lane_gpa);
        }
    }

done:
    LOG("recon thread done — pipe server remains active");
    // Do NOT close g_log — pipe clients still write to it.
    // Do NOT return 0 and exit — just let this thread die; pipe server thread lives on.
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DllMain — attach spawns recon thread; detach is intentionally ignored
// ═══════════════════════════════════════════════════════════════════════════════

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, ReconThread, nullptr, 0, nullptr);

    // DLL_PROCESS_DETACH is intentionally NOT handled.
    // FreeLibrary on this DLL will corrupt VBox VMM state and crash BlueStacks.
    // Inject once. Leave it. If you need to update recon, restart BlueStacks.
    return TRUE;
}