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

// ── virtual address space scan for PVM magic ─────────────────────────────────
// Walk the entire VA space with VirtualQuery. For each committed readable
// region, scan for the PVM magic dword. When found, derive UVM via VMR3GetUVM.

struct FindResult { PVM pVM; PUVM pUVM; };

static FindResult ScanVASpace()
{
    FindResult res = {};
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);

    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;

    uint64_t scanned = 0;
    uint64_t hits    = 0;

    while (addr < end && !res.pUVM) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }

        size_t regionSize = mbi.RegionSize;

        // only scan committed, readable, non-guard pages
        // skip image-backed pages (those are the DLL sections we already scanned)
        bool readable  = (mbi.State == MEM_COMMIT);
        bool hasRead   = (mbi.Protect & 0xFF) != PAGE_NOACCESS &&
                         (mbi.Protect & 0xFF) != PAGE_EXECUTE &&
                         !(mbi.Protect & PAGE_GUARD);
        bool notImage  = (mbi.Type != MEM_IMAGE); // skip DLL/EXE sections

        if (readable && hasRead && notImage && regionSize >= 4) {
            scanned += regionSize;
            uint8_t* p   = (uint8_t*)addr;
            uint8_t* pEnd = p + regionSize - 3;

            while (p < pEnd) {
                __try {
                    if (*(uint32_t*)p == VM_MAGIC) {
                        hits++;
                        PVM pvm = (PVM)p;
                        // try to get UVM from this PVM
                        PUVM uvm = g_fnGetUVM(pvm);
                        if (uvm && (uintptr_t)uvm >= 0x10000) {
                            if (IsRealUVM(uvm)) {
                                LOG("[recon] PVM magic at %p → UVM=%p", p, uvm);
                                res.pVM  = pvm;
                                res.pUVM = uvm;
                                return res;
                            }
                        }
                        p += 8; // skip ahead past this hit
                    } else {
                        p += 4;
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    p += 0x1000; // skip faulting page
                }
            }
        }

        addr += regionSize;
    }

    LOG("[recon] VA scan complete: %.1f MB scanned, %llu magic hits, UVM not confirmed",
        scanned / (1024.0 * 1024.0), (unsigned long long)hits);
    return res;
}

// ── main thread ───────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);

    g_log = fopen(LOG_PATH, "w");
    LOG("[recon] started pid=%u", GetCurrentProcessId());

    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("[recon] BstkVMM.dll not loaded"); goto done; }

    {
        MODULEINFO mi = {};
        GetModuleInformation(GetCurrentProcess(), hVMM, &mi, sizeof(mi));
        LOG("[recon] BstkVMM.dll base=%p size=0x%X", (void*)hVMM, mi.SizeOfImage);

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

        LOG("[recon] scanning VA space for PVM magic (0x%08X)...", VM_MAGIC);
        FindResult vm = ScanVASpace();

        if (!vm.pUVM) { LOG("[recon] UVM not found"); goto done; }

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