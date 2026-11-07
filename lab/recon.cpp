/*
 * recon.dll v3 — VirtualBox guest RAM recon
 * Target:  HD-Player.exe (BlueStacks 5+)
 * Compile: x64, MSVC or clang-cl
 *
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * Changes from v2:
 *   – DumpFuncBytes: logs first 64 bytes of each export as hex.
 *     Tells us exactly what VMR3GetUVM and PGMR3PhysGetRamRangeCount
 *     actually do — are they reading from a global? do they check the arg?
 *
 *   – NullArgTest: calls g_fnRangeCount(NULL) and g_fnGetState(NULL).
 *     If those also return 0xFFFFFFFF / 31, the functions ignore their
 *     argument entirely and read from a global instead.
 *
 *   – QueryTargetHVA: VirtualQuery on TARGET_HVA. Gives us the guest RAM
 *     region base and size for free. If guest RAM starts at GPA 0, then
 *     GPA = TARGET_HVA − region_base. We test this with a live read.
 *
 *   – WalkPVMStruct: for each PVM candidate from the VA scan, dumps the
 *     first 256 struct bytes and brute-forces every 8-byte aligned field
 *     as a potential pUVM, testing each via g_fnRangeCount. Finds the
 *     real pUVM offset even if BlueStacks moved it.
 *
 *   – ScanForHCPtr: scans all readable non-image private/mapped memory
 *     for RTHCUINTPTR values that land inside the guest RAM region found
 *     by QueryTargetHVA. Those are HCPtrStart candidates — they anchor
 *     the PGMPHYSRANGEINFO structs, which is part of the PVM/PGM layout.
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

typedef struct {
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

// HVA of lane value from CE — stable within session, shifts on restart.
#define TARGET_HVA  ((uintptr_t)0x2BDE7F7335CULL)
#define LOG_PATH    "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static const uint32_t VM_MAGIC = 0x0fd00fd0;

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

// ── guest RAM region (filled by QueryTargetHVA) ───────────────────────────────

static uintptr_t g_guestRAMBase = 0;   // HCPtrStart of first range
static uintptr_t g_guestRAMSize = 0;   // size of that region

// ── 1. function byte dump ─────────────────────────────────────────────────────
//
// Logs first 64 bytes of a function as 4 rows of 16 hex bytes.
// In 99% of cases this is enough to see: does the function dereference
// RCX (its first argument), does it call into something else, does it
// return a constant, does it read from a RIP-relative global?

static void DumpFuncBytes(const char* name, void* fn)
{
    if (!fn) return;
    uint8_t* p = (uint8_t*)fn;
    LOG("[func] %s @ %p", name, fn);
    __try {
        for (int row = 0; row < 4; row++) {
            char buf[80]; char* out = buf;
            for (int col = 0; col < 16; col++)
                out += sprintf_s(out, (size_t)(buf + sizeof(buf) - out), "%02X ", p[row * 16 + col]);
            LOG("[func]   +%02d: %s", row * 16, buf);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[func]   (read threw)");
    }
}

// ── 2. null-arg test ──────────────────────────────────────────────────────────
//
// If g_fnRangeCount(NULL) also returns 0xFFFFFFFF and g_fnGetState(NULL)
// also returns 31, those functions are not dereferencing their argument.
// They're reading from a process-global or ring-0 shared region.

static void NullArgTest()
{
    LOG("[nullarg] calling RangeCount(NULL) and GetState(NULL)");

    uint32_t rc_null = 0xDEAD;
    unsigned st_null = 0xDEAD;
    bool rcThrew = false, stThrew = false;

    __try { rc_null = g_fnRangeCount(nullptr); } __except(EXCEPTION_EXECUTE_HANDLER) { rcThrew = true; }
    __try { st_null = g_fnGetState(nullptr);   } __except(EXCEPTION_EXECUTE_HANDLER) { stThrew = true; }

    LOG("[nullarg] RangeCount(NULL)=%u%s", rc_null, rcThrew ? " THREW" : "");
    LOG("[nullarg] GetState(NULL)=%u%s",   st_null, stThrew ? " THREW" : "");
    LOG("[nullarg] conclusion: RangeCount %s argument",
        rcThrew ? "CRASHES on" :
        rc_null == 0xFFFFFFFF ? "IGNORES (returns same 0xFFFFFFFF)" :
        "USES (returned different value)");
    LOG("[nullarg] conclusion: GetState %s argument",
        stThrew ? "CRASHES on" :
        st_null == 31 ? "IGNORES (returns same 31)" :
        "USES (returned different value)");
}

// ── 3. VirtualQuery on TARGET_HVA ─────────────────────────────────────────────
//
// Since we're injected into HD-Player.exe, we can VirtualQuery the lane HVA
// directly. This tells us the guest RAM region boundaries without any VBox API.
//
// If guest RAM starts at GPA 0x00000000 (standard VBox x86 layout), then:
//     GPA = TARGET_HVA − region_AllocationBase
//
// We test this assumption with a direct dereference (we're inside the process)
// and compare the value to what CE reported (-1/0/1).

static void QueryTargetHVA()
{
    LOG("[hva] querying TARGET_HVA=0x%016llX", (unsigned long long)TARGET_HVA);

    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery((void*)TARGET_HVA, &mbi, sizeof(mbi))) {
        LOG("[hva] VirtualQuery failed le=%u", GetLastError());
        return;
    }

    const char* typStr = mbi.Type  == MEM_PRIVATE ? "PRIVATE" :
                         mbi.Type  == MEM_MAPPED  ? "MAPPED"  :
                         mbi.Type  == MEM_IMAGE   ? "IMAGE"   : "?";
    const char* stStr  = mbi.State == MEM_COMMIT  ? "COMMIT"  :
                         mbi.State == MEM_RESERVE ? "RESERVE" : "FREE";

    LOG("[hva] BaseAddress    = %p", mbi.BaseAddress);
    LOG("[hva] AllocationBase = %p", mbi.AllocationBase);
    LOG("[hva] RegionSize     = 0x%llX (%.1f MB)",
        (unsigned long long)mbi.RegionSize,
        mbi.RegionSize / (1024.0 * 1024.0));
    LOG("[hva] State=%s  Type=%s  Protect=%02X", stStr, typStr, mbi.Protect & 0xFF);

    // Store for ScanForHCPtr
    g_guestRAMBase = (uintptr_t)mbi.AllocationBase;
    g_guestRAMSize = mbi.RegionSize;

    uintptr_t offsetInRegion = TARGET_HVA - (uintptr_t)mbi.AllocationBase;
    LOG("[hva] offset in region = 0x%llX", (unsigned long long)offsetInRegion);
    LOG("[hva] estimated GPA (if GCPhysStart=0) = 0x%016llX", (unsigned long long)offsetInRegion);

    // Direct dereference — we ARE inside the process
    if (mbi.State == MEM_COMMIT &&
        (mbi.Protect & PAGE_NOACCESS) == 0 &&
        (mbi.Protect & PAGE_GUARD)    == 0)
    {
        int32_t laneVal = 0xDEAD;
        bool threw = false;
        __try { laneVal = *(int32_t*)TARGET_HVA; }
        __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

        if (!threw)
            LOG("[hva] direct read: lane=%d  (expect -1, 0, or 1)", laneVal);
        else
            LOG("[hva] direct read threw (page not accessible from this thread?)");
    }

    // Now try PGMPhysSimpleReadGCPhys at estimated GPA, using the two VA-scan PVM
    // candidates as PVM argument. Even if UVM is wrong, the PVM arg might work.
    // (Logged below by WalkPVMStruct after it finds pUVM.)
    LOG("[hva] estimated GPA stored: 0x%016llX", (unsigned long long)offsetInRegion);
}

// ── 4. PVM struct walk ────────────────────────────────────────────────────────
//
// For a PVM candidate found by magic scan:
//   a) Dump first 256 bytes as hex (shows struct layout in the log)
//   b) Walk every 8-byte field 0–512 and try it as pUVM via g_fnRangeCount.
//      Fields that return ranges in [1,128] are strong pUVM candidates.
//   c) For each promising candidate, also try g_fnGetRange(candidate, 0, &info)
//      and log the first range. If it matches g_guestRAMBase, we have full
//      confirmation.
//   d) Try PGMPhysSimpleReadGCPhys at the estimated GPA using the pVM directly
//      (some BlueStacks builds have PGMR3 functions that accept PVM, not PUVM).

static void WalkPVMStruct(PVM pvm, uintptr_t estimatedGPA)
{
    LOG("[walk] PVM candidate @ %p", pvm);
    uint8_t* base = (uint8_t*)pvm;

    // ── a) hex dump first 256 bytes ───────────────────────────────────────────
    LOG("[walk] struct bytes (first 256):");
    __try {
        for (int row = 0; row < 16; row++) {
            char hex[80]; char* out = hex;
            int rowOff = row * 16;
            for (int col = 0; col < 16; col++)
                out += sprintf_s(out, (size_t)(hex + sizeof(hex) - out),
                                 "%02X ", base[rowOff + col]);
            // show 8-byte pointer at start of this row
            uintptr_t ptr = *(uintptr_t*)(base + rowOff);
            out += sprintf_s(out, 32, " ptr=%016llX", (unsigned long long)ptr);
            LOG("[walk]   +%03X: %s", rowOff, hex);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[walk]   hex dump threw at some row");
    }

    // ── b) field walk: try each 8-byte offset as pUVM ─────────────────────────
    LOG("[walk] field walk (testing each offset as pUVM via RangeCount):");
    bool foundAny = false;

    for (int off = 0; off <= 512; off += 8) {
        __try {
            uintptr_t val = *(uintptr_t*)(base + off);
            if (val < 0x10000 || val > 0x7FFFFFFFFFFFULL) continue;

            uint32_t ranges = 0xDEAD;
            bool threw = false;
            __try { ranges = g_fnRangeCount((PUVM)val); }
            __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

            if (threw) continue;  // silent skip for throws

            // Log ANY result that isn't the sentinel 0xFFFFFFFF
            if (ranges != 0xFFFFFFFF) {
                LOG("[walk]   offset +%03X  val=%016llX  ranges=%u  *** NON-SENTINEL ***",
                    off, (unsigned long long)val, ranges);
                foundAny = true;

                if (ranges >= 1 && ranges <= 128) {
                    LOG("[walk]   *** PROMISING pUVM at offset +%03X ***", off);

                    // Also get state and GetVM
                    unsigned state = 0xDEAD;
                    PVM gotPVM = nullptr;
                    __try { state  = g_fnGetState((PUVM)val); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                    __try { gotPVM = g_fnGetVM((PUVM)val);    } __except(EXCEPTION_EXECUTE_HANDLER) {}

                    uint32_t gotMagic = 0;
                    __try { if (gotPVM) gotMagic = *(uint32_t*)gotPVM; }
                    __except(EXCEPTION_EXECUTE_HANDLER) {}

                    LOG("[walk]   state=%u  GetVM=%p  magic=%08X", state, gotPVM, gotMagic);

                    // Try GetRange to get HCPtrStart
                    PGMPHYSRANGEINFO info = {};
                    int rc = -1;
                    __try { rc = g_fnGetRange((PUVM)val, 0, &info); }
                    __except(EXCEPTION_EXECUTE_HANDLER) {}

                    LOG("[walk]   GetRange(0): rc=%d  GC=%016llX-%016llX  HC=%016llX  mapped=%d",
                        rc,
                        (unsigned long long)info.GCPhysStart,
                        (unsigned long long)info.GCPhysEnd,
                        (unsigned long long)info.HCPtrStart,
                        (int)info.fHasMapping);

                    if (g_guestRAMBase && info.HCPtrStart == g_guestRAMBase)
                        LOG("[walk]   *** HCPtrStart MATCHES guest RAM region — CONFIRMED ***");
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }

    if (!foundAny)
        LOG("[walk]   no non-sentinel ranges found (all fields returned 0xFFFFFFFF)");

    // ── c) try functions with pvm directly (swapped role test) ───────────────
    // Some BlueStacks builds accept PVM where standard VBox expects PUVM.
    LOG("[walk] direct PVM-as-PUVM tests:");
    {
        uint32_t rDirect = 0xDEAD; bool rThrew = false;
        unsigned sDirect = 0xDEAD; bool sThrew = false;
        __try { rDirect = g_fnRangeCount((PUVM)pvm); } __except(EXCEPTION_EXECUTE_HANDLER) { rThrew = true; }
        __try { sDirect = g_fnGetState((PUVM)pvm);   } __except(EXCEPTION_EXECUTE_HANDLER) { sThrew = true; }
        LOG("[walk]   RangeCount(pvm)=%u%s", rDirect, rThrew ? " THREW" : "");
        LOG("[walk]   GetState(pvm)=%u%s",   sDirect, sThrew ? " THREW" : "");

        if (!rThrew && rDirect >= 1 && rDirect <= 128) {
            LOG("[walk]   *** PVM accepted as PUVM by RangeCount! ranges=%u ***", rDirect);
            PGMPHYSRANGEINFO info = {};
            int rc = -1;
            __try { rc = g_fnGetRange((PUVM)pvm, 0, &info); }
            __except(EXCEPTION_EXECUTE_HANDLER) {}
            LOG("[walk]   GetRange(pvm,0): rc=%d  GC=%016llX  HC=%016llX",
                rc,
                (unsigned long long)info.GCPhysStart,
                (unsigned long long)info.HCPtrStart);
        }
    }

    // ── d) direct read at estimated GPA using pvm as PVM arg ─────────────────
    if (estimatedGPA != 0 && !g_fnRead) return;
    if (estimatedGPA != 0) {
        int32_t val = 0xDEAD;
        int rc = -1;
        bool threw = false;
        __try { rc = g_fnRead(pvm, &val, (RTGCPHYS)estimatedGPA, sizeof(val)); }
        __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }
        LOG("[walk]   Read(pvm, GPA=0x%llX): rc=%d  val=%d%s",
            (unsigned long long)estimatedGPA, rc, val, threw ? " THREW" : "");
        if (rc == VINF_SUCCESS)
            LOG("[walk]   *** lane=%d (expect -1/0/1) — PVM is correct ***", val);
    }
}

// ── 5. scan for HCPtr values inside the guest RAM region ──────────────────────
//
// Walk all readable non-image private/mapped memory.
// Any 8-byte aligned value that falls INSIDE [g_guestRAMBase, g_guestRAMBase+size)
// is a potential HCPtrStart stored somewhere — likely inside PGMPHYSRANGEINFO,
// which lives inside the PVM's pgm component.
// If we find such a value, the 8 bytes BEFORE it are GCPhysStart of that range,
// which lets us compute GPA = GCPhysStart + (TARGET_HVA − HCPtrStart).

static void ScanForHCPtr()
{
    if (!g_guestRAMBase || !g_guestRAMSize) {
        LOG("[hcptr] guest RAM region unknown, skipping");
        return;
    }

    LOG("[hcptr] scanning for HCPtr values in [%016llX, %016llX)",
        (unsigned long long)g_guestRAMBase,
        (unsigned long long)(g_guestRAMBase + g_guestRAMSize));

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;

    uint32_t found = 0;

    while (addr < end && found < 32) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }

        size_t sz = mbi.RegionSize;
        bool ok = (mbi.State  == MEM_COMMIT) &&
                  (mbi.Type   != MEM_IMAGE)  &&
                  (mbi.Protect & 0xFF) != PAGE_NOACCESS &&
                  (mbi.Protect & 0xFF) != PAGE_EXECUTE  &&
                  !(mbi.Protect & PAGE_GUARD) &&
                  sz >= 8;

        if (ok) {
            uint8_t* p    = (uint8_t*)addr;
            uint8_t* pEnd = p + sz - 7;
            while (p < pEnd) {
                __try {
                    uintptr_t val = *(uintptr_t*)p;
                    if (val >= g_guestRAMBase && val < g_guestRAMBase + g_guestRAMSize) {
                        // This looks like an HCPtrStart. The PGMPHYSRANGEINFO layout is:
                        //   GCPhysStart (+0, 8 bytes)
                        //   GCPhysEnd   (+8, 8 bytes)
                        //   HCPtrStart  (+16, 8 bytes)
                        //   fHasMapping (+24, 1 byte)
                        // So GCPhysStart is at p - 16.
                        RTGCPHYS gcStart = 0, gcEnd = 0;
                        __try {
                            gcStart = *(RTGCPHYS*)(p - 16);
                            gcEnd   = *(RTGCPHYS*)(p -  8);
                        } __except(EXCEPTION_EXECUTE_HANDLER) {}

                        uint64_t rangeSize = (gcEnd > gcStart) ? (gcEnd - gcStart + 1) : 0;
                        RTGCPHYS estimatedGPA = gcStart + (RTGCPHYS)(TARGET_HVA - val);

                        LOG("[hcptr] HCPtr=%016llX @ addr=%p  GC:%016llX-%016llX  sz=%.1fMB",
                            (unsigned long long)val, p,
                            (unsigned long long)gcStart,
                            (unsigned long long)gcEnd,
                            rangeSize / (1024.0 * 1024.0));
                        LOG("[hcptr]   estimated GPA for TARGET_HVA = 0x%016llX",
                            (unsigned long long)estimatedGPA);

                        // Also try to find which PVM owns this by scanning backwards
                        // for VM_MAGIC from p (the PGMPHYSRANGEINFO is embedded in PVM.pgm)
                        found++;
                        p += 8;
                        continue;
                    }
                    p += 8;
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    p += 0x1000;
                }
            }
        }

        addr += sz;
    }

    if (found == 0)
        LOG("[hcptr] no HCPtr values found in guest RAM range");
    else
        LOG("[hcptr] found %u HCPtr candidate(s)", found);
}

// ── VA space scan (from v2, simplified) ──────────────────────────────────────

struct PVMHit { PVM pvm; };
static PVMHit g_pvmHits[8];
static int    g_nPVMHits = 0;

static void CollectPVMHits()
{
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;
    uint64_t  scanned = 0, hits = 0;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }
        size_t sz = mbi.RegionSize;

        bool ok = (mbi.State  == MEM_COMMIT) &&
                  (mbi.Type   != MEM_IMAGE)  &&
                  (mbi.Protect & 0xFF) != PAGE_NOACCESS &&
                  (mbi.Protect & 0xFF) != PAGE_EXECUTE  &&
                  !(mbi.Protect & PAGE_GUARD) &&
                  sz >= 4;

        if (ok) {
            scanned += sz;
            uint8_t* p    = (uint8_t*)addr;
            uint8_t* pEnd = p + sz - 3;
            while (p < pEnd) {
                __try {
                    if (*(uint32_t*)p == VM_MAGIC && g_nPVMHits < 8) {
                        hits++;
                        LOG("[vascan] VM_MAGIC @ %p  region=%p  type=%s",
                            p, mbi.AllocationBase,
                            mbi.Type == MEM_PRIVATE ? "PRIVATE" : "MAPPED");
                        g_pvmHits[g_nPVMHits++].pvm = (PVM)p;
                        p += 8;
                    } else {
                        p += 4;
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) { p += 0x1000; }
            }
        }

        addr += sz;
    }

    LOG("[vascan] %.1f MB scanned, %llu VM_MAGIC hits",
        scanned / (1024.0 * 1024.0), (unsigned long long)hits);
}

// ── main thread ───────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);

    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon] log open failed\n"); return 0; }

    LOG("[recon] v3  pid=%u", GetCurrentProcessId());

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

        // ── 1. function byte dumps ────────────────────────────────────────────
        LOG("=== FUNCTION BYTES ===");
        DumpFuncBytes("VMR3GetUVM",                g_fnGetUVM);
        DumpFuncBytes("VMR3GetVM",                 g_fnGetVM);
        DumpFuncBytes("VMR3GetState",              g_fnGetState);
        DumpFuncBytes("PGMR3PhysGetRamRangeCount", g_fnRangeCount);
        DumpFuncBytes("PGMR3PhysGetRange",         g_fnGetRange);
        DumpFuncBytes("PGMPhysSimpleReadGCPhys",   g_fnRead);
        DumpFuncBytes("PGMPhysSimpleWriteGCPhys",  g_fnWrite);

        // ── 2. null-arg test ──────────────────────────────────────────────────
        LOG("=== NULL ARG TEST ===");
        NullArgTest();

        // ── 3. query TARGET_HVA region ────────────────────────────────────────
        LOG("=== TARGET HVA REGION ===");
        QueryTargetHVA();

        // ── 4. VA scan + struct walk ──────────────────────────────────────────
        LOG("=== VA SCAN + STRUCT WALK ===");
        CollectPVMHits();

        uintptr_t estimatedGPA = (g_guestRAMBase && TARGET_HVA >= g_guestRAMBase)
                                 ? (TARGET_HVA - g_guestRAMBase)
                                 : 0;
        LOG("[recon] estimated GPA for struct walk reads: 0x%016llX", (unsigned long long)estimatedGPA);

        for (int i = 0; i < g_nPVMHits; i++) {
            LOG("--- PVM hit %d ---", i + 1);
            WalkPVMStruct(g_pvmHits[i].pvm, estimatedGPA);
        }

        // ── 5. scan for HCPtr in guest RAM region ─────────────────────────────
        LOG("=== HCPTR SCAN ===");
        ScanForHCPtr();

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