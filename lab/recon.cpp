/*
 * recon.dll — VirtualBox guest RAM recon
 * Target:  HD-Player.exe (BlueStacks 5+)
 * Compile: x64, MSVC or clang-cl
 *
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>

// ── types ────────────────────────────────────────────────────────────────────

typedef void*     PUVM;
typedef void*     PVM;
typedef uint64_t  RTGCPHYS;
typedef uintptr_t RTHCUINTPTR;
#define VINF_SUCCESS 0

typedef struct PGMPHYSRANGEINFO {
    RTGCPHYS    GCPhysStart;
    RTGCPHYS    GCPhysEnd;
    RTHCUINTPTR HCPtrStart;
    bool        fHasMapping;
} PGMPHYSRANGEINFO;

typedef PUVM     (WINAPI* pfnVMR3GetUVM)               (PVM pVM);
typedef PVM      (WINAPI* pfnVMR3GetVM)                (PUVM pUVM);
typedef unsigned (WINAPI* pfnVMR3GetState)             (PUVM pUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PUVM pUVM);
typedef int      (WINAPI* pfnPGMR3PhysGetRange)        (PUVM pUVM, uint32_t iRange, PGMPHYSRANGEINFO* pInfo);
typedef int      (WINAPI* pfnPGMPhysSimpleReadGCPhys)  (PVM pVM, void* pvDst, RTGCPHYS GCPhysSrc, size_t cb);
typedef int      (WINAPI* pfnPGMPhysSimpleWriteGCPhys) (PVM pVM, RTGCPHYS GCPhysDst, const void* pvSrc, size_t cb);

#define LANE_GPA  ((RTGCPHYS)0)
#define LOG_PATH  "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static FILE* g_log = nullptr;
#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    char _buf[512]; sprintf_s(_buf, fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(_buf); \
} while(0)

static const uint32_t VM_MAGIC = 0x0fd00fd0;

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnVMR3GetState              g_fnGetState;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;

// ── UVM validation ────────────────────────────────────────────────────────────

static bool IsRealUVM(PUVM candidate)
{
    if (!candidate || (uintptr_t)candidate < 0x10000) return false;
    __try {
        uint32_t ranges = g_fnRangeCount(candidate);
        if (ranges < 2 || ranges > 32) return false;
        unsigned state = g_fnGetState(candidate);
        if (state < 1 || state > 10)   return false;
        PVM pvm = g_fnGetVM(candidate);
        if (!pvm || (uintptr_t)pvm < 0x10000) return false;
        if (*(uint32_t*)pvm != VM_MAGIC) return false;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ── thread stack scan ─────────────────────────────────────────────────────────
// Suspend each thread except ours, walk its stack looking for pointers
// that pass IsRealUVM. Focus on threads whose RSP/RIP is inside BstkVMM.dll.

struct FindResult { PVM pVM; PUVM pUVM; };

static FindResult ScanThreadStacks(uintptr_t vmmBase, size_t vmmSize)
{
    FindResult res = {};
    DWORD myTid  = GetCurrentThreadId();
    DWORD myPid  = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return res;

    THREADENTRY32 te = { sizeof(te) };
    if (!Thread32First(snap, &te)) { CloseHandle(snap); return res; }

    do {
        if (te.th32OwnerProcessID != myPid) continue;
        if (te.th32ThreadID == myTid)       continue;

        HANDLE hThread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            FALSE, te.th32ThreadID);
        if (!hThread) continue;

        DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount == (DWORD)-1) { CloseHandle(hThread); continue; }

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(hThread, &ctx)) {
            uintptr_t rip = ctx.Rip;
            uintptr_t rsp = ctx.Rsp;
            bool inVMM = (rip >= vmmBase && rip < vmmBase + vmmSize);

            // log every thread briefly
            LOG("[thread] tid=%u  RIP=%016llX  RSP=%016llX  %s",
                te.th32ThreadID,
                (unsigned long long)rip,
                (unsigned long long)rsp,
                inVMM ? "<<< IN BstkVMM" : "");

            // scan 4KB of stack from RSP
            uintptr_t stackTop = rsp;
            for (uintptr_t p = stackTop; p < stackTop + 0x1000; p += 8) {
                void* candidate = nullptr;
                __try { candidate = *(void**)p; } __except(1) { continue; }
                if (IsRealUVM((PUVM)candidate)) {
                    LOG("[recon] UVM on stack of tid=%u at RSP+0x%llX → %p",
                        te.th32ThreadID,
                        (unsigned long long)(p - stackTop),
                        candidate);
                    res.pUVM = (PUVM)candidate;
                    res.pVM  = g_fnGetVM(res.pUVM);
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    CloseHandle(snap);
                    return res;
                }
            }

            // also check registers directly
            uintptr_t regs[] = {
                ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9,
                ctx.Rdi, ctx.Rsi, ctx.Rbx, ctx.Rbp
            };
            for (int r = 0; r < 8; r++) {
                if (IsRealUVM((PUVM)(void*)regs[r])) {
                    LOG("[recon] UVM in register of tid=%u reg[%d]=%016llX",
                        te.th32ThreadID, r, (unsigned long long)regs[r]);
                    res.pUVM = (PUVM)(void*)regs[r];
                    res.pVM  = g_fnGetVM(res.pUVM);
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    CloseHandle(snap);
                    return res;
                }
            }
        }

        ResumeThread(hThread);
        CloseHandle(hThread);

    } while (Thread32Next(snap, &te) && !res.pUVM);

    CloseHandle(snap);
    return res;
}

// ── main thread ───────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    // give BlueStacks a moment to settle after inject before we snapshot threads
    Sleep(500);

    g_log = fopen(LOG_PATH, "w");
    LOG("[recon] started pid=%u", GetCurrentProcessId());

    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("[recon] BstkVMM.dll not loaded"); goto done; }

    {
        MODULEINFO mi = {};
        GetModuleInformation(GetCurrentProcess(), hVMM, &mi, sizeof(mi));
        LOG("[recon] BstkVMM.dll base=%p size=0x%X",
            (void*)hVMM, mi.SizeOfImage);

#define RESOLVE(name, type, global) \
        global = (type)GetProcAddress(hVMM, #name); \
        if (!global) { LOG("[recon] missing: " #name); goto done; } \
        LOG("[recon] " #name " = %p", (void*)global);

        RESOLVE(VMR3GetUVM,                pfnVMR3GetUVM,                g_fnGetUVM)
        RESOLVE(VMR3GetVM,                 pfnVMR3GetVM,                 g_fnGetVM)
        RESOLVE(VMR3GetState,              pfnVMR3GetState,              g_fnGetState)
        RESOLVE(PGMR3PhysGetRamRangeCount, pfnPGMR3PhysGetRamRangeCount, g_fnRangeCount)
#undef RESOLVE

        auto fnGetRange = (pfnPGMR3PhysGetRange)      GetProcAddress(hVMM, "PGMR3PhysGetRange");
        auto fnRead     = (pfnPGMPhysSimpleReadGCPhys) GetProcAddress(hVMM, "PGMPhysSimpleReadGCPhys");
        auto fnWrite    = (pfnPGMPhysSimpleWriteGCPhys)GetProcAddress(hVMM, "PGMPhysSimpleWriteGCPhys");
        if (!fnGetRange || !fnRead || !fnWrite) {
            LOG("[recon] missing range/read/write"); goto done;
        }

        // ── thread stack scan ─────────────────────────────────────────────────
        LOG("[recon] scanning thread stacks for UVM...");
        uintptr_t vmmBase = (uintptr_t)mi.lpBaseOfDll;
        size_t    vmmSize = mi.SizeOfImage;

        FindResult vm = ScanThreadStacks(vmmBase, vmmSize);

        if (!vm.pUVM) { LOG("[recon] UVM not found on any thread stack"); goto done; }

        LOG("[recon] UVM=%p  PVM=%p", vm.pUVM, (void*)vm.pVM);

        // ── RAM range table ───────────────────────────────────────────────────
        uint32_t nRanges = g_fnRangeCount(vm.pUVM);
        LOG("[recon] RAM ranges: %u", nRanges);
        LOG("[recon] %-4s  %-18s  %-18s  %-18s  %s",
            "idx", "GCPhysStart", "GCPhysEnd", "HCVirtStart", "size(MB)");

        uint64_t total = 0;
        for (uint32_t i = 0; i < nRanges; i++) {
            PGMPHYSRANGEINFO info = {};
            int rc = fnGetRange(vm.pUVM, i, &info);
            if (rc != VINF_SUCCESS) { LOG("[recon]   range %u failed rc=%d", i, rc); continue; }
            uint64_t sz = info.GCPhysEnd - info.GCPhysStart + 1;
            total += sz;
            LOG("[recon]   [%2u]  GC:%016llX-%016llX  HC:%016llX  %.1f MB%s",
                i,
                (unsigned long long)info.GCPhysStart,
                (unsigned long long)info.GCPhysEnd,
                (unsigned long long)info.HCPtrStart,
                sz / (1024.0 * 1024.0),
                info.fHasMapping ? "" : "  (no HC mapping)");
        }
        LOG("[recon] total guest RAM: %.1f MB", total / (1024.0 * 1024.0));

        // ── optional lane GPA read ────────────────────────────────────────────
        if (LANE_GPA != 0 && vm.pVM) {
            int32_t val = 0;
            int rc = fnRead(vm.pVM, &val, LANE_GPA, sizeof(val));
            if (rc == VINF_SUCCESS)
                LOG("[recon] LANE_GPA=0x%llX  value=%d", (unsigned long long)LANE_GPA, val);
            else
                LOG("[recon] LANE_GPA read failed rc=%d", rc);
        }

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