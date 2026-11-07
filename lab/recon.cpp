/*
 * recon.dll v7 — range table dump + HVA→GPA translation
 * Engine: BstkVMM.dll (VirtualBox internal, BlueStacks 5)
 * Compile: cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * Root cause of prior throws: pVM pages were cold (lazy-commit).
 * Fix: prefault pVM before calling PGMR3PhysGetRange.
 *
 * This version:
 *   1. Prefaults pVM[0..0x4000] with a volatile read loop
 *   2. Dumps all 20 RAM ranges (GCPhysStart, GCPhysEnd, HCPtrStart, size)
 *   3. Accepts a TARGET_HVA compile constant; translates it to GPA
 *      using the range table and logs the stable guest physical address
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>

typedef void*     PUVM;
typedef void*     PVM;
typedef uint64_t  RTGCPHYS;
typedef uintptr_t RTHCUINTPTR;
#define VINF_SUCCESS 0

static const uint32_t UVM_MAGIC = 0x19700823;

// ── set this to your current CE lane address each session ────────────────────
// If you don't have one yet, set to 0 and just read the range table output.
static const uintptr_t TARGET_HVA = 0x000002BDE7F7335C;   // ← paste CE address here

typedef struct {
    RTGCPHYS    GCPhysStart;    // +0x00
    RTGCPHYS    GCPhysEnd;      // +0x08
    RTHCUINTPTR HCPtrStart;     // +0x10
    bool        fHasMapping;    // +0x18
    uint8_t     _pad[39];
} PGMPHYSRANGEINFO;

typedef PUVM     (WINAPI* pfnVMR3GetUVM)               (PVM);
typedef PVM      (WINAPI* pfnVMR3GetVM)                (PUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PUVM);
typedef int      (WINAPI* pfnPGMR3PhysGetRange)        (PUVM, uint32_t, uintptr_t, PGMPHYSRANGEINFO*);
typedef int      (WINAPI* pfnPGMPhysSimpleReadGCPhys)  (PVM, void*, RTGCPHYS, size_t);
typedef int      (WINAPI* pfnPGMPhysSimpleWriteGCPhys) (PVM, RTGCPHYS, const void*, size_t);

#define LOG_PATH "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;
static pfnPGMR3PhysGetRange         g_fnGetRange;
static pfnPGMPhysSimpleReadGCPhys   g_fnRead;
static pfnPGMPhysSimpleWriteGCPhys  g_fnWrite;

static FILE* g_log = nullptr;

#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    char _buf[512]; \
    sprintf_s(_buf, sizeof(_buf), fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(_buf); \
} while(0)

struct Handles { PUVM pUVM; PVM pVM; uint32_t nRanges; bool valid; };

// ── prefault ──────────────────────────────────────────────────────────────────
// Touch every page in [base, base+size) with a volatile read.
// Forces the OS to page in lazy-committed memory before we call into VBox.

static void Prefault(void* base, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)base;
    size_t pages = (size + 0xFFF) / 0x1000;
    for (size_t i = 0; i < pages; i++) {
        __try { (void)p[i * 0x1000]; }
        __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ── UVM scan ──────────────────────────────────────────────────────────────────

static Handles ScanForUVM()
{
    Handles result = {};
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
                        PVM pvm = nullptr;
                        __try { pvm = *(PVM*)(pg + 8); }
                        __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (!pvm) { pg += 0x1000; continue; }

                        PVM  gotPVM = nullptr;
                        PUVM gotUVM = nullptr;
                        __try { gotPVM = g_fnGetVM((PUVM)pg); }
                        __except(EXCEPTION_EXECUTE_HANDLER) {}
                        __try { gotUVM = g_fnGetUVM(pvm); }
                        __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (gotPVM != pvm || gotUVM != (PUVM)pg)
                            { pg += 0x1000; continue; }

                        // Prefault pVM before RangeCount
                        Prefault(pvm, 0x4000);

                        uint32_t rc = 0;
                        __try { rc = g_fnRangeCount((PUVM)pvm); }
                        __except(EXCEPTION_EXECUTE_HANDLER) {}

                        if (rc >= 1 && rc <= 128) {
                            LOG("[uvm] pUVM=%p pVM=%p nRanges=%u", (void*)pg, pvm, rc);
                            result = { (PUVM)pg, pvm, rc, true };
                            return result; // take first valid
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
                pg += 0x1000;
            }
        }
        addr += rSize;
    }
    return result;
}

// ── range table dump + HVA translation ───────────────────────────────────────

static RTGCPHYS DumpRangesAndTranslate(Handles* h)
{
    RTGCPHYS laneGPA = (RTGCPHYS)-1;

    LOG("[ranges] %-4s  %-18s  %-18s  %-18s  %s",
        "idx", "GCPhysStart", "GCPhysEnd", "HCPtrStart", "size");

    uint64_t totalMB = 0;

    for (uint32_t i = 0; i < h->nRanges && i < 64; i++) {
        PGMPHYSRANGEINFO info = {};
        int rc = -1; bool threw = true;
        __try {
            rc    = g_fnGetRange((PUVM)h->pVM, i, 0, &info);
            threw = false;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        if (threw)            { LOG("[ranges] [%2u] threw", i);        continue; }
        if (rc != VINF_SUCCESS){ LOG("[ranges] [%2u] rc=%d", i, rc);   continue; }

        uint64_t sz = info.GCPhysEnd >= info.GCPhysStart
                    ? (info.GCPhysEnd - info.GCPhysStart + 1) : 0;
        totalMB += sz;

        LOG("[ranges] [%2u]  GC:%016llX-%016llX  HC:%016llX  %8.2f MB",
            i,
            (unsigned long long)info.GCPhysStart,
            (unsigned long long)info.GCPhysEnd,
            (unsigned long long)info.HCPtrStart,
            sz / (1024.0 * 1024.0));

        // HVA→GPA translation
        if (TARGET_HVA != 0 && info.HCPtrStart != 0) {
            uintptr_t hcStart = (uintptr_t)info.HCPtrStart;
            uintptr_t hcEnd   = hcStart + sz;
            if (TARGET_HVA >= hcStart && TARGET_HVA < hcEnd) {
                laneGPA = info.GCPhysStart + (TARGET_HVA - hcStart);
                LOG("[ranges]   *** HVA 0x%016llX is in this range ***",
                    (unsigned long long)TARGET_HVA);
                LOG("[ranges]   *** LANE GPA = 0x%016llX (stable across restarts) ***",
                    (unsigned long long)laneGPA);
            }
        }
    }

    LOG("[ranges] total: %.1f MB", totalMB / (1024.0 * 1024.0));

    if (TARGET_HVA != 0 && laneGPA == (RTGCPHYS)-1)
        LOG("[ranges] TARGET_HVA 0x%016llX not found in any range — rescan with CE this session",
            (unsigned long long)TARGET_HVA);

    return laneGPA;
}

// ── verify: read lane GPA and confirm value is -1/0/1 ────────────────────────

static void VerifyLaneGPA(Handles* h, RTGCPHYS gpa)
{
    if (gpa == (RTGCPHYS)-1) return;

    int32_t lane = 0xDEAD;
    int rc = -1; bool threw = false;
    __try { rc = g_fnRead(h->pVM, &lane, gpa, sizeof(lane)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

    LOG("[verify] GPA=%016llX  rc=%d  threw=%d  lane=%d",
        (unsigned long long)gpa, rc, (int)threw, lane);

    if (!threw && rc == VINF_SUCCESS && (lane >= -1 && lane <= 1))
        LOG("[verify] *** LANE VALUE CONFIRMED: %d — ready for bot ***", lane);
    else
        LOG("[verify] unexpected value — HVA may be stale, rescan with CE");
}

// ── main ──────────────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);
    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon] fopen failed\n"); return 0; }
    LOG("[recon] v7  TARGET_HVA=0x%016llX", (unsigned long long)TARGET_HVA);

    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("[recon] no BstkVMM.dll"); goto done; }

#define RESOLVE(name, type, var) \
    var = (type)GetProcAddress(hVMM, #name); \
    if (!var) { LOG("[recon] missing " #name); goto done; } \
    LOG("[recon] " #name " = %p", (void*)var);

    RESOLVE(VMR3GetUVM,                pfnVMR3GetUVM,                g_fnGetUVM)
    RESOLVE(VMR3GetVM,                 pfnVMR3GetVM,                 g_fnGetVM)
    RESOLVE(PGMR3PhysGetRamRangeCount, pfnPGMR3PhysGetRamRangeCount, g_fnRangeCount)
    RESOLVE(PGMPhysSimpleReadGCPhys,   pfnPGMPhysSimpleReadGCPhys,   g_fnRead)
    RESOLVE(PGMPhysSimpleWriteGCPhys,  pfnPGMPhysSimpleWriteGCPhys,  g_fnWrite)
#undef RESOLVE

    g_fnGetRange = (pfnPGMR3PhysGetRange)GetProcAddress(hVMM, "PGMR3PhysGetRange");
    if (!g_fnGetRange) { LOG("[recon] missing PGMR3PhysGetRange"); goto done; }
    LOG("[recon] PGMR3PhysGetRange = %p", (void*)g_fnGetRange);

    {
        Handles h = ScanForUVM();
        if (!h.valid) { LOG("[recon] no UVM"); goto done; }

        LOG("=== RANGE TABLE ===");
        RTGCPHYS laneGPA = DumpRangesAndTranslate(&h);

        LOG("=== LANE VERIFY ===");
        VerifyLaneGPA(&h, laneGPA);

        LOG("[recon] done.");
    }

done:
    if (g_log) { fclose(g_log); g_log = nullptr; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, ReconThread, nullptr, 0, nullptr);
    return TRUE;
}