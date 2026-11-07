/*
 * recon.dll v4 — VirtualBox guest RAM recon
 * Target:  HD-Player.exe (BlueStacks 5+)
 * Compile: x64, MSVC or clang-cl
 *
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * What v3 taught us (from function byte analysis):
 *
 *  VMR3GetVM    @ +32: cmp [rcx], 0x19700823  → real UVM magic in this build
 *               @ +48: mov rax, [rcx+8]; ret  → PVM is stored at UVM+8
 *
 *  VMR3GetUVM   @ +48: cmp [rcx], 0x1E        → takes PVM (checks cCpus ≤ 30)
 *  PGMR3PhysGetRamRangeCount: same cCpus check → also takes PVM
 *  PGMPhysSimpleRead/WriteGCPhys: mov rdi/rsi, rcx → take PVM as first arg
 *
 *  PGMR3PhysGetRange: saves R9 to rsi at entry  → 4-arg signature; call with extra=0
 *
 *  VMR3GetState / PGMR3PhysGetRamRangeCount: return sentinel (31 / 0xFFFFFFFF)
 *  when called with wrong magic → explains every failure in v2/v3.
 *
 *  TARGET_HVA: State=FREE in v3 → CE address is from prior game run, stale.
 *  We skip it entirely. Once we have the range table, do a fresh CE scan and
 *  feed the new HVA back (see LOG output for instructions).
 *
 * What v4 does:
 *   1. Scan ALL committed non-image private/mapped memory at PAGE-ALIGNED
 *      addresses only for first dword == 0x19700823 → PUVM candidates
 *   2. For each PUVM:
 *        pVM = *(void**)(pUVM + 8)              [from VMR3GetVM disasm]
 *        try RangeCount(pVM)   -- should work   (cCpus ≤ 30 check passes)
 *        try RangeCount(pUVM)  -- probably fails (0x19700823 >> 30)
 *        log both so we confirm which handle each function expects
 *   3. With the working handle, dump the full range table
 *   4. Test-read 16 bytes at GPA 0x0 using pVM to confirm read path
 *   5. Log HCPtrStart values and instruction for the user to get the lane GPA
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>

// ── types ────────────────────────────────────────────────────────────────────

typedef void*     PUVM;
typedef void*     PVM;
typedef uint64_t  RTGCPHYS;
typedef uintptr_t RTHCUINTPTR;
#define VINF_SUCCESS 0

// UVM magic discovered from VMR3GetVM disassembly:
//   81 39 23 08 70 19  =  cmp dword ptr [rcx], 0x19700823
static const uint32_t UVM_MAGIC = 0x19700823;

typedef struct {
    RTGCPHYS    GCPhysStart;    // +0x00  (8 bytes)
    RTGCPHYS    GCPhysEnd;      // +0x08  (8 bytes)
    RTHCUINTPTR HCPtrStart;     // +0x10  (8 bytes)
    bool        fHasMapping;    // +0x18  (1 byte)
} PGMPHYSRANGEINFO;

typedef PUVM     (WINAPI* pfnVMR3GetUVM)               (PVM pVM);
typedef PVM      (WINAPI* pfnVMR3GetVM)                (PUVM pUVM);
typedef unsigned (WINAPI* pfnVMR3GetState)             (PUVM pUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PUVM pUVM);  // actually takes PVM in this build
// PGMR3PhysGetRange has a 4-arg signature in this BlueStacks build (R9 is saved on entry).
// Pass dwExtra=0; the 4th arg appears to be unused or a flags field.
typedef int      (WINAPI* pfnPGMR3PhysGetRange)        (PUVM pUVM, uint32_t iRange, uintptr_t dwExtra, PGMPHYSRANGEINFO* pInfo);
typedef int      (WINAPI* pfnPGMPhysSimpleReadGCPhys)  (PVM pVM, void* pvDst, RTGCPHYS GCPhysSrc, size_t cb);
typedef int      (WINAPI* pfnPGMPhysSimpleWriteGCPhys) (PVM pVM, RTGCPHYS GCPhysDst, const void* pvSrc, size_t cb);

#define LOG_PATH    "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnVMR3GetState              g_fnGetState;
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

// ── handle pair ───────────────────────────────────────────────────────────────

struct Handles {
    PUVM pUVM;          // struct with magic 0x19700823; accepted by VMR3GetVM
    PVM  pVM;           // struct at pUVM+8; accepted by PGMR3Phys* and PGMPhysSimple*
    PUVM rangeHandle;   // whichever of pUVM/pVM PGMR3PhysGetRamRangeCount accepts
    uint32_t nRanges;
    bool valid;
};

// ── UVM scan ──────────────────────────────────────────────────────────────────
//
// Walk all committed non-image pages, checking ONLY page-aligned addresses.
// Reduces false-positive rate vs scanning every 4 bytes, since VMR3GetVM
// rejects any pointer where rcx & 0xFFF != 0.

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
        bool    noExec = (mbi.Protect & 0xFF) != PAGE_NOACCESS &&
                         (mbi.Protect & 0xFF) != PAGE_EXECUTE  &&
                         !(mbi.Protect & PAGE_GUARD);
        bool    noImg  = (mbi.Type    != MEM_IMAGE);

        if (commit && noExec && noImg && rSize >= 4) {
            uintptr_t rBase = (uintptr_t)mbi.BaseAddress;
            uintptr_t rEnd  = rBase + rSize;

            // first page-aligned address at or after rBase
            uintptr_t pg = (rBase + 0xFFF) & ~(uintptr_t)0xFFF;

            while (pg + 4 <= rEnd) {
                pagesChecked++;
                __try {
                    if (*(uint32_t*)pg == UVM_MAGIC) {
                        hits++;

                        LOG("[uvmscan] UVM_MAGIC @ %p  region=%p  sz=0x%llX  type=%s",
                            (void*)pg, mbi.AllocationBase,
                            (unsigned long long)rSize,
                            mbi.Type == MEM_PRIVATE ? "PRIVATE" : "MAPPED");

                        // Read PVM pointer at UVM+8  (from VMR3GetVM: mov rax,[rcx+8])
                        PVM pvm = nullptr;
                        bool readThrew = false;
                        __try { pvm = *(PVM*)(pg + 8); }
                        __except(EXCEPTION_EXECUTE_HANDLER) { readThrew = true; }
                        LOG("[uvmscan]   UVM+8 (pVM ptr) = %p%s", pvm, readThrew ? " (read threw)" : "");

                        // Also dump 48 bytes of struct so we can see the layout
                        LOG("[uvmscan]   struct bytes +0:");
                        __try {
                            uint8_t* b = (uint8_t*)pg;
                            for (int row = 0; row < 3; row++) {
                                char hex[64]; char* out = hex;
                                for (int col = 0; col < 16; col++)
                                    out += sprintf_s(out, (size_t)(hex+sizeof(hex)-out),
                                                     "%02X ", b[row*16+col]);
                                LOG("[uvmscan]     +%02d: %s", row*16, hex);
                            }
                        } __except(EXCEPTION_EXECUTE_HANDLER) {}

                        // Test: call VMR3GetVM — should validate magic and return pVM
                        PVM gotPVM = nullptr;
                        bool getVMThrew = false;
                        __try { gotPVM = g_fnGetVM((PUVM)pg); }
                        __except(EXCEPTION_EXECUTE_HANDLER) { getVMThrew = true; }
                        LOG("[uvmscan]   VMR3GetVM(pUVM)=%p%s%s",
                            gotPVM, getVMThrew ? " (threw)" : "",
                            (gotPVM && gotPVM == pvm) ? " *** MATCHES UVM+8 ***" : "");

                        // Test: RangeCount with pUVM (probably fails: 0x19700823 > 30)
                        uint32_t rcUVM = 0xDEAD;
                        bool rcUVMThrew = false;
                        __try { rcUVM = g_fnRangeCount((PUVM)pg); }
                        __except(EXCEPTION_EXECUTE_HANDLER) { rcUVMThrew = true; }
                        LOG("[uvmscan]   RangeCount(pUVM)=%u%s", rcUVM, rcUVMThrew?" THREW":"");

                        // Test: RangeCount with pVM (cCpus check ≤ 30, should work)
                        uint32_t rcPVM = 0xDEAD;
                        bool rcPVMThrew = false;
                        if (pvm && !readThrew) {
                            __try { rcPVM = g_fnRangeCount((PUVM)pvm); }
                            __except(EXCEPTION_EXECUTE_HANDLER) { rcPVMThrew = true; }
                            LOG("[uvmscan]   RangeCount(pVM) =%u%s", rcPVM, rcPVMThrew?" THREW":"");
                        }

                        // Also test GetUVM(pVM) — should return back our pUVM
                        PUVM gotUVM = nullptr;
                        if (pvm && !readThrew) {
                            __try { gotUVM = g_fnGetUVM(pvm); }
                            __except(EXCEPTION_EXECUTE_HANDLER) {}
                            LOG("[uvmscan]   VMR3GetUVM(pVM) =%p%s",
                                gotUVM,
                                (gotUVM == (PUVM)pg) ? " *** ROUND-TRIP OK ***" : "");
                        }

                        // Also test GetState with both handles
                        unsigned stUVM = 0xDEAD, stPVM = 0xDEAD;
                        __try { stUVM = g_fnGetState((PUVM)pg); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (pvm && !readThrew) {
                            __try { stPVM = g_fnGetState((PUVM)pvm); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        }
                        LOG("[uvmscan]   GetState(pUVM)=%u  GetState(pVM)=%u", stUVM, stPVM);

                        // Pick range handle
                        bool uvmOk = (rcUVM >= 1 && rcUVM <= 128);
                        bool pvmOk = (rcPVM >= 1 && rcPVM <= 128);
                        if (uvmOk || pvmOk) {
                            LOG("[uvmscan]   *** WORKING RANGE HANDLE FOUND ***");
                            result.pUVM        = (PUVM)pg;
                            result.pVM         = pvm;
                            result.rangeHandle = uvmOk ? (PUVM)pg : (PUVM)pvm;
                            result.nRanges     = uvmOk ? rcUVM : rcPVM;
                            result.valid       = true;
                            // Keep scanning to log all hits, but stop after first valid
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}

                pg += 0x1000;
            }
        }

        addr += rSize;
    }

    LOG("[uvmscan] scanned %llu page-aligned addresses, %llu UVM_MAGIC hits",
        (unsigned long long)pagesChecked,
        (unsigned long long)hits);

    return result;
}

// ── range table dump ──────────────────────────────────────────────────────────

static void DumpRangeTable(Handles* h)
{
    if (!h->valid || !h->rangeHandle) return;

    LOG("[ranges] using handle=%p  nRanges=%u", h->rangeHandle, h->nRanges);
    LOG("[ranges] %-4s  %-18s  %-18s  %-18s  %-10s  %s",
        "idx", "GCPhysStart", "GCPhysEnd", "HCVirtStart", "size(MB)", "flags");

    uint64_t totalGB = 0;
    for (uint32_t i = 0; i < h->nRanges && i < 64; i++) {
        PGMPHYSRANGEINFO info = {};
        int rc = -1;
        bool threw = false;
        __try {
            // 4-arg call: pass dwExtra=0
            rc = g_fnGetRange(h->rangeHandle, i, 0, &info);
        } __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

        if (threw) { LOG("[ranges]   [%2u] threw", i); continue; }
        if (rc != VINF_SUCCESS) { LOG("[ranges]   [%2u] rc=%d", i, rc); continue; }

        uint64_t sz = info.GCPhysEnd - info.GCPhysStart + 1;
        totalGB += sz;

        LOG("[ranges]   [%2u]  GC:%016llX-%016llX  HC:%016llX  %8.1f MB  %s",
            i,
            (unsigned long long)info.GCPhysStart,
            (unsigned long long)info.GCPhysEnd,
            (unsigned long long)info.HCPtrStart,
            sz / (1024.0 * 1024.0),
            info.fHasMapping ? "mapped" : "NO-HC-MAPPING");
    }
    LOG("[ranges] total guest RAM: %.1f MB", totalGB / (1024.0 * 1024.0));
}

// ── test read at GPA 0x0 ──────────────────────────────────────────────────────
//
// Read the first 16 bytes of guest physical address 0.
// In a typical x86 VM, GPA 0 is the low BIOS / IVT area.
// Any non-garbage result confirms the PVM and read path are correct.

static void TestReadGPA0(Handles* h)
{
    if (!h->valid || !h->pVM) return;

    LOG("[readtest] PGMPhysSimpleReadGCPhys(pVM=%p, GPA=0x0, cb=16)", h->pVM);

    uint8_t buf[16] = {};
    int rc = -1;
    bool threw = false;
    __try { rc = g_fnRead(h->pVM, buf, 0, sizeof(buf)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

    if (threw) { LOG("[readtest] THREW"); return; }

    char hex[64]; char* out = hex;
    for (int i = 0; i < 16; i++) out += sprintf_s(out, 4, "%02X ", buf[i]);
    LOG("[readtest] rc=%d  bytes: %s", rc, hex);

    if (rc == VINF_SUCCESS)
        LOG("[readtest] *** READ SUCCEEDED — PVM is confirmed correct ***");
    else
        LOG("[readtest] read failed (rc=%d)", rc);
}

// ── post-confirmation instructions ───────────────────────────────────────────
//
// Once range table is live, tell the user how to get the lane GPA via CE.

static void PrintNextSteps(Handles* h)
{
    if (!h->valid) return;

    LOG("=== NEXT STEPS TO FIND LANE GPA ===");
    LOG("Range table is now live. The guest RAM HCPtrStart values above");
    LOG("show where BlueStacks has mapped guest physical memory into the host process.");
    LOG("");
    LOG("To find the lane value GPA:");
    LOG("  1. Leave the game running and open Cheat Engine attached to HD-Player.exe");
    LOG("  2. Scan for the lane value (-1, 0, or 1) as int32");
    LOG("  3. Navigate a lane; rescan for the new value; repeat until 1-4 addresses remain");
    LOG("  4. Note the winning HVA (e.g. 0x2BDE7F7335C from the last session)");
    LOG("  5. Run the new bot DLL with that HVA — it will:");
    LOG("       for each range i in the table:");
    LOG("         if HVA in [HCPtrStart, HCPtrStart + rangeSize):");
    LOG("           GPA = GCPhysStart + (HVA - HCPtrStart)");
    LOG("           print GPA — this is the stable lane address across restarts");
    LOG("");
    LOG("Or: paste those HCPtrStart values and ask for the bot DLL directly.");
    LOG("    The bot will scan guest RAM for the lane value at boot without needing CE.");
}

// ── main thread ───────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);

    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon] log open failed\n"); return 0; }

    LOG("[recon] v4  pid=%u", GetCurrentProcessId());

    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("[recon] BstkVMM.dll not loaded"); goto done; }

    {
        MODULEINFO mi = {};
        GetModuleInformation(GetCurrentProcess(), hVMM, &mi, sizeof(mi));
        LOG("[recon] BstkVMM.dll base=%p size=0x%X", (void*)hVMM, mi.SizeOfImage);

#define RESOLVE(name, type, global) \
        global = (type)GetProcAddress(hVMM, #name); \
        if (!global) { LOG("[recon] missing export: " #name); goto done; } \
        LOG("[recon] " #name " = %p", (void*)global);

        RESOLVE(VMR3GetUVM,                pfnVMR3GetUVM,                g_fnGetUVM)
        RESOLVE(VMR3GetVM,                 pfnVMR3GetVM,                 g_fnGetVM)
        RESOLVE(VMR3GetState,              pfnVMR3GetState,              g_fnGetState)
        RESOLVE(PGMR3PhysGetRamRangeCount, pfnPGMR3PhysGetRamRangeCount, g_fnRangeCount)
        RESOLVE(PGMR3PhysGetRange,         pfnPGMR3PhysGetRange,         g_fnGetRange)
        RESOLVE(PGMPhysSimpleReadGCPhys,   pfnPGMPhysSimpleReadGCPhys,   g_fnRead)
        RESOLVE(PGMPhysSimpleWriteGCPhys,  pfnPGMPhysSimpleWriteGCPhys,  g_fnWrite)
#undef RESOLVE

        // ── scan for real UVM ─────────────────────────────────────────────────
        LOG("=== UVM SCAN (magic=0x%08X, page-aligned only) ===", UVM_MAGIC);
        Handles h = ScanForUVM();

        LOG("=== SELECTION ===");
        LOG("[select] valid=%s  pUVM=%p  pVM=%p  rangeHandle=%p  nRanges=%u",
            h.valid ? "YES" : "NO",
            h.pUVM, h.pVM, h.rangeHandle, h.nRanges);

        if (!h.valid) {
            LOG("[recon] no valid UVM found");
            LOG("[recon] if zero UVM_MAGIC hits: BlueStacks may have changed the magic again;");
            LOG("[recon] disassemble VMR3GetVM at %p for the cmp immediate", (void*)g_fnGetVM);
            goto done;
        }

        // ── range table ───────────────────────────────────────────────────────
        LOG("=== RANGE TABLE ===");
        DumpRangeTable(&h);

        // ── GPA 0 test read ───────────────────────────────────────────────────
        LOG("=== GPA 0x0 TEST READ ===");
        TestReadGPA0(&h);

        // ── next steps ────────────────────────────────────────────────────────
        PrintNextSteps(&h);

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