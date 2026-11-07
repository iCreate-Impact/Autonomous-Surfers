/*
 * recon.dll v5 — diagnose PGMR3PhysGetRange throwing
 * Engine: BstkVMM.dll (VirtualBox internal, BlueStacks 5)
 * Compile: x64 MSVC
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * Changes from v4:
 *   - Disassemble first 80 bytes of PGMR3PhysGetRange and log them
 *     so we can read the actual signature from the prolog
 *   - Try three call signatures:
 *       A: (pVM, iRange, 0,    &info)   — current 4-arg with dwExtra
 *       B: (pVM, iRange, &info)         — 3-arg, no dwExtra
 *       C: (pVM, 0,      iRange, &info) — swapped handle type
 *   - Pad PGMPHYSRANGEINFO to 64 bytes so an oversized struct write
 *     doesn't AV inside the function
 *   - Everything else identical to v4
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

// Padded to 64 bytes — if the real struct is larger than our guess,
// the function writes into padding instead of past the allocation.
typedef struct {
    RTGCPHYS    GCPhysStart;    // +0x00
    RTGCPHYS    GCPhysEnd;      // +0x08
    RTHCUINTPTR HCPtrStart;     // +0x10
    bool        fHasMapping;    // +0x18
    uint8_t     _pad[39];       // +0x19 .. +0x3F  (pad to 64 bytes)
} PGMPHYSRANGEINFO;

typedef PUVM     (WINAPI* pfnVMR3GetUVM)               (PVM);
typedef PVM      (WINAPI* pfnVMR3GetVM)                (PUVM);
typedef unsigned (WINAPI* pfnVMR3GetState)             (PUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PUVM);

// Three candidate signatures — we'll try all three
typedef int (WINAPI* pfnGetRange4)(PUVM, uint32_t, uintptr_t, PGMPHYSRANGEINFO*); // A: 4-arg
typedef int (WINAPI* pfnGetRange3)(PUVM, uint32_t, PGMPHYSRANGEINFO*);            // B: 3-arg
typedef int (WINAPI* pfnGetRange4s)(PUVM, uintptr_t, uint32_t, PGMPHYSRANGEINFO*);// C: swapped

typedef int (WINAPI* pfnPGMPhysSimpleReadGCPhys) (PVM, void*, RTGCPHYS, size_t);
typedef int (WINAPI* pfnPGMPhysSimpleWriteGCPhys)(PVM, RTGCPHYS, const void*, size_t);

#define LOG_PATH "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnVMR3GetState              g_fnGetState;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;
static void*                        g_fnGetRangeRaw;   // raw pointer, cast per trial
static pfnPGMPhysSimpleReadGCPhys   g_fnRead;
static pfnPGMPhysSimpleWriteGCPhys  g_fnWrite;

static FILE* g_log = nullptr;

#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    char _buf[512]; \
    sprintf_s(_buf, sizeof(_buf), fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(_buf); \
} while(0)

struct Handles {
    PUVM     pUVM;
    PVM      pVM;
    PUVM     rangeHandle;
    uint32_t nRanges;
    bool     valid;
};

// ── disassemble helper ────────────────────────────────────────────────────────
// Just dumps raw bytes; paste into https://disasm.pro or x64dbg to read.

static void DisasmDump(const char* label, void* fn, int bytes)
{
    LOG("[disasm] %s @ %p — first %d bytes:", label, fn, bytes);
    uint8_t* p = (uint8_t*)fn;
    for (int row = 0; row < bytes; row += 16) {
        char hex[64]; char* out = hex;
        int cols = (bytes - row < 16) ? bytes - row : 16;
        for (int c = 0; c < cols; c++)
            out += sprintf_s(out, 4, "%02X ", p[row + c]);
        LOG("[disasm]   +%03d: %s", row, hex);
    }
}

// ── UVM scan (unchanged from v4) ─────────────────────────────────────────────

static Handles ScanForUVM()
{
    Handles result = {};
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;
    uint64_t pagesChecked = 0, hits = 0;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }

        size_t  rSize  = mbi.RegionSize;
        bool    commit = (mbi.State   == MEM_COMMIT);
        bool    noExec = ((mbi.Protect & 0xFF) != PAGE_NOACCESS) &&
                         ((mbi.Protect & 0xFF) != PAGE_EXECUTE)  &&
                         !(mbi.Protect & PAGE_GUARD);
        bool    noImg  = (mbi.Type != MEM_IMAGE);

        if (commit && noExec && noImg && rSize >= 4) {
            uintptr_t rBase = (uintptr_t)mbi.BaseAddress;
            uintptr_t rEnd  = rBase + rSize;
            uintptr_t pg    = (rBase + 0xFFF) & ~(uintptr_t)0xFFF;

            while (pg + 4 <= rEnd) {
                pagesChecked++;
                __try {
                    if (*(uint32_t*)pg == UVM_MAGIC) {
                        hits++;
                        LOG("[uvmscan] UVM_MAGIC @ %p", (void*)pg);

                        PVM pvm = nullptr;
                        bool threw = false;
                        __try { pvm = *(PVM*)(pg + 8); }
                        __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

                        if (!pvm || threw) { pg += 0x1000; continue; }

                        PVM  gotPVM = nullptr;
                        PUVM gotUVM = nullptr;
                        __try { gotPVM = g_fnGetVM((PUVM)pg); }   __except(EXCEPTION_EXECUTE_HANDLER) {}
                        __try { gotUVM = g_fnGetUVM(pvm); }       __except(EXCEPTION_EXECUTE_HANDLER) {}

                        if (gotPVM != pvm || gotUVM != (PUVM)pg) { pg += 0x1000; continue; }

                        uint32_t rc = 0;
                        __try { rc = g_fnRangeCount((PUVM)pvm); } __except(EXCEPTION_EXECUTE_HANDLER) {}

                        LOG("[uvmscan]   round-trip OK  pUVM=%p pVM=%p nRanges=%u", (void*)pg, pvm, rc);

                        if (rc >= 1 && rc <= 128) {
                            result.pUVM        = (PUVM)pg;
                            result.pVM         = pvm;
                            result.rangeHandle = (PUVM)pvm;
                            result.nRanges     = rc;
                            result.valid       = true;
                            LOG("[uvmscan]   *** selected ***");
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
                pg += 0x1000;
            }
        }
        addr += rSize;
    }
    LOG("[uvmscan] scanned %llu pages, %llu hits", pagesChecked, hits);
    return result;
}

// ── range table with signature trials ────────────────────────────────────────

static void DumpRangeTable(Handles* h)
{
    if (!h->valid) return;

    // First: dump the function bytes so we can inspect the prolog
    DisasmDump("PGMR3PhysGetRange", g_fnGetRangeRaw, 80);

    LOG("[ranges] nRanges=%u  handle=%p", h->nRanges, h->rangeHandle);
    LOG("[ranges] %-4s  %-18s  %-18s  %-18s  sig", "idx", "GCPhys", "GCPhysEnd", "HCVirt");

    for (uint32_t i = 0; i < h->nRanges && i < 64; i++) {
        PGMPHYSRANGEINFO infoA = {}, infoB = {}, infoC = {};
        int rcA = -1, rcB = -1, rcC = -1;
        bool threwA = true, threwB = true, threwC = true;

        // Sig A: (pVM, iRange, 0, &info)
        __try {
            rcA = ((pfnGetRange4)g_fnGetRangeRaw)(h->rangeHandle, i, 0, &infoA);
            threwA = false;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        // Sig B: (pVM, iRange, &info) — no dwExtra
        __try {
            rcB = ((pfnGetRange3)g_fnGetRangeRaw)(h->rangeHandle, i, &infoB);
            threwB = false;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        // Sig C: (pVM, 0, iRange, &info) — swapped slot order
        __try {
            rcC = ((pfnGetRange4s)g_fnGetRangeRaw)(h->rangeHandle, 0, i, &infoC);
            threwC = false;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        // Log whichever didn't throw and returned success
        if (!threwA && rcA == VINF_SUCCESS) {
            uint64_t sz = infoA.GCPhysEnd - infoA.GCPhysStart + 1;
            LOG("[ranges] [%2u] GC:%016llX-%016llX HC:%016llX %.1fMB  sigA",
                i, infoA.GCPhysStart, infoA.GCPhysEnd, infoA.HCPtrStart, sz/1048576.0);
        } else if (!threwB && rcB == VINF_SUCCESS) {
            uint64_t sz = infoB.GCPhysEnd - infoB.GCPhysStart + 1;
            LOG("[ranges] [%2u] GC:%016llX-%016llX HC:%016llX %.1fMB  sigB",
                i, infoB.GCPhysStart, infoB.GCPhysEnd, infoB.HCPtrStart, sz/1048576.0);
        } else if (!threwC && rcC == VINF_SUCCESS) {
            uint64_t sz = infoC.GCPhysEnd - infoC.GCPhysStart + 1;
            LOG("[ranges] [%2u] GC:%016llX-%016llX HC:%016llX %.1fMB  sigC",
                i, infoC.GCPhysStart, infoC.GCPhysEnd, infoC.HCPtrStart, sz/1048576.0);
        } else {
            LOG("[ranges] [%2u] all sigs threw/failed: A=%s(rc=%d) B=%s(rc=%d) C=%s(rc=%d)",
                i,
                threwA?"threw":("rc"), rcA,
                threwB?"threw":("rc"), rcB,
                threwC?"threw":("rc"), rcC);
        }
    }
}

// ── test read ─────────────────────────────────────────────────────────────────

static void TestReadGPA0(Handles* h)
{
    if (!h->valid) return;
    uint8_t buf[16] = {};
    int rc = -1;
    bool threw = false;
    __try { rc = g_fnRead(h->pVM, buf, 0, 16); }
    __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

    char hex[64]; char* out = hex;
    for (int i = 0; i < 16; i++) out += sprintf_s(out, 4, "%02X ", buf[i]);
    LOG("[readtest] rc=%d threw=%d  bytes: %s", rc, (int)threw, hex);
}

// ── main thread ───────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);
    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon] log open failed\n"); return 0; }
    LOG("[recon] v5");

    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("[recon] BstkVMM.dll not loaded"); goto done; }

#define RESOLVE(name, type, global) \
    global = (type)GetProcAddress(hVMM, #name); \
    if (!global) { LOG("[recon] missing: " #name); goto done; } \
    LOG("[recon] " #name " = %p", (void*)global);

    RESOLVE(VMR3GetUVM,                pfnVMR3GetUVM,                g_fnGetUVM)
    RESOLVE(VMR3GetVM,                 pfnVMR3GetVM,                 g_fnGetVM)
    RESOLVE(VMR3GetState,              pfnVMR3GetState,              g_fnGetState)
    RESOLVE(PGMR3PhysGetRamRangeCount, pfnPGMR3PhysGetRamRangeCount, g_fnRangeCount)
    g_fnGetRangeRaw = GetProcAddress(hVMM, "PGMR3PhysGetRange");
    if (!g_fnGetRangeRaw) { LOG("[recon] missing: PGMR3PhysGetRange"); goto done; }
    LOG("[recon] PGMR3PhysGetRange = %p", g_fnGetRangeRaw);
    RESOLVE(PGMPhysSimpleReadGCPhys,   pfnPGMPhysSimpleReadGCPhys,   g_fnRead)
    RESOLVE(PGMPhysSimpleWriteGCPhys,  pfnPGMPhysSimpleWriteGCPhys,  g_fnWrite)
#undef RESOLVE

    {
        LOG("=== UVM SCAN ===");
        Handles h = ScanForUVM();
        LOG("=== RANGE TABLE ===");
        DumpRangeTable(&h);
        LOG("=== GPA 0 READ ===");
        TestReadGPA0(&h);
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