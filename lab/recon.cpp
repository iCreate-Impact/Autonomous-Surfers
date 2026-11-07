/*
 * recon.dll v8 — bypass PGMR3PhysGetRange entirely
 * Walk the PGM range linked list directly from pVM+0x1010
 *
 * From v6 disasm (+118): mov rcx, [rbx+0x1010]
 * rbx = pVM → pVM+0x1010 = pRamRangesXR3 (linked list head)
 *
 * PGMRAMRANGE layout (stock VBox 6.x, confirmed via open source):
 *   +0x00  RTGCPHYS  GCPhys        (range start)
 *   +0x08  RTGCPHYS  GCPhysLast    (range end, inclusive)
 *   +0x10  RTHCPTR   pvR3          (host virtual — what we need)
 *   +0x18  uint32_t  cb            (size in bytes)
 *   +0x1C  uint32_t  fFlags
 *   +0x20  RTGCPHYS  GCPhysHC      (may differ in patched builds)
 *   +0x28  ptr       pSelfR0
 *   +0x30  ptr       pFirstR0      ← not what we want
 *   ... (lots of internal stuff)
 *   somewhere: ptr pNextR3         (next range in list)
 *
 * We'll scan for pNextR3 empirically: walk +0x00 to +0x100 looking
 * for a pointer that lands in the same allocation as the current node
 * OR is null (end of list). Log everything so we can see the layout.
 *
 * Compile: cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
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

static const uint32_t UVM_MAGIC   = 0x19700823;
static const uint32_t PGM_RANGES_OFFSET = 0x1010; // pVM+0x1010 = pRamRangesXR3

static const uintptr_t TARGET_HVA = 0x000002BDE7F7335C;

typedef PUVM     (WINAPI* pfnVMR3GetUVM)               (PVM);
typedef PVM      (WINAPI* pfnVMR3GetVM)                (PUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PUVM);
typedef int      (WINAPI* pfnPGMPhysSimpleReadGCPhys)  (PVM, void*, RTGCPHYS, size_t);
typedef int      (WINAPI* pfnPGMPhysSimpleWriteGCPhys) (PVM, RTGCPHYS, const void*, size_t);

#define LOG_PATH "X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt"

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;
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

static void Prefault(void* base, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)base;
    size_t pages = (size + 0xFFF) / 0x1000;
    for (size_t i = 0; i < pages; i++)
        __try { (void)p[i * 0x1000]; } __except(EXCEPTION_EXECUTE_HANDLER) {}
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

                        Prefault(pvm, 0x2000);

                        uint32_t rc = 0;
                        __try { rc = g_fnRangeCount((PUVM)pvm); }
                        __except(EXCEPTION_EXECUTE_HANDLER) {}

                        if (rc >= 1 && rc <= 128) {
                            LOG("[uvm] pUVM=%p pVM=%p nRanges=%u", (void*)pg, pvm, rc);
                            result = { (PUVM)pg, pvm, rc, true };
                            return result;
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

// ── dump first 256 bytes of a node ───────────────────────────────────────────

static void DumpNodeLayout(uintptr_t node, int idx)
{
    LOG("[node%d] layout of PGMRAMRANGE @ %p:", idx, (void*)node);
    for (int row = 0; row < 256; row += 16) {
        char hex[64]; char* out = hex;
        bool ok = true;
        __try {
            uint8_t* b = (uint8_t*)(node + row);
            for (int c = 0; c < 16; c++)
                out += sprintf_s(out, 4, "%02X ", b[c]);
        } __except(EXCEPTION_EXECUTE_HANDLER) { ok = false; }
        if (!ok) { LOG("[node%d]   +%03d: (fault)", idx, row); break; }
        LOG("[node%d]   +%03d: %s", idx, row, hex);
    }
}

// ── walk the linked list directly ────────────────────────────────────────────
//
// pVM+0x1010 → pRamRangesXR3 (head of PGMRAMRANGE singly-linked list)
//
// PGMRAMRANGE layout we care about:
//   +0x00  GCPhys       (uint64 range start GPA)
//   +0x08  GCPhysLast   (uint64 range end GPA, inclusive)
//   +0x10  pvR3         (uint64 host virtual base of this range)
//   +0x18  cb           (uint32 size in bytes)
//
// pNextR3 is somewhere past +0x18. We find it by scanning for a pointer
// that is either null (end of list) or points to memory where [ptr+0]
// looks like a GPA (small aligned value). Log the first node's full
// layout so we can confirm the pNextR3 offset.

static RTGCPHYS WalkRangeList(Handles* h)
{
    RTGCPHYS laneGPA = (RTGCPHYS)-1;

    uintptr_t headPtr = 0;
    __try { headPtr = *(uintptr_t*)((uintptr_t)h->pVM + PGM_RANGES_OFFSET); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[walk] pVM+0x1010 read threw");
        return laneGPA;
    }

    LOG("[walk] pVM+0x%04X (pRamRangesXR3) = %p", PGM_RANGES_OFFSET, (void*)headPtr);
    if (!headPtr) { LOG("[walk] null head — no ranges"); return laneGPA; }

    // Prefault the first node
    Prefault((void*)headPtr, 0x1000);

    // Dump the first node's raw bytes so we can find pNextR3 offset
    DumpNodeLayout(headPtr, 0);

    // Now walk: scan offsets 0x20..0x100 in the first node for pNextR3
    // We identify it as the first pointer-aligned slot that is either:
    //   null  → end of list (valid but tells us nothing about offset)
    //   ptr   → points somewhere with [ptr+0] being a valid GPA
    uint32_t nextOff = 0;
    for (uint32_t off = 0x20; off <= 0x100; off += 8) {
        uintptr_t candidate = 0;
        bool threw = false;
        __try { candidate = *(uintptr_t*)(headPtr + off); }
        __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }
        if (threw || candidate == 0) continue;

        // canonical check
        if ((candidate >> 48) != 0 && (candidate >> 48) != 0xFFFF) continue;

        // check target is readable and [+0] looks like a GPA
        uint64_t t0 = 0;
        bool t0threw = false;
        __try { t0 = *(uint64_t*)candidate; }
        __except(EXCEPTION_EXECUTE_HANDLER) { t0threw = true; }
        if (t0threw) continue;

        bool plausible = (t0 == 0) || (t0 < 0x100000000ULL && (t0 & 0xFFF) == 0);
        if (plausible) {
            LOG("[walk] pNextR3 candidate at node+0x%02X = %p (target[0]=%016llX)",
                off, (void*)candidate, (unsigned long long)t0);
            if (nextOff == 0) nextOff = off; // take first hit
        }
    }

    if (nextOff == 0) {
        LOG("[walk] couldn't find pNextR3 offset — dumping all pointer slots:");
        for (uint32_t off = 0x20; off <= 0x100; off += 8) {
            uintptr_t v = 0;
            __try { v = *(uintptr_t*)(headPtr + off); }
            __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (v) LOG("[walk]   node+0x%02X = %016llX", off, (unsigned long long)v);
        }
        return laneGPA;
    }

    LOG("[walk] using pNextR3 offset = +0x%02X", nextOff);
    LOG("[walk] %-4s  %-18s  %-18s  %-18s  %s",
        "idx", "GCPhysStart", "GCPhysEnd", "HCPtrStart", "size");

    uintptr_t node = headPtr;
    int idx = 0;
    while (node && idx < 64) {
        Prefault((void*)node, 0x200);

        uint64_t gcStart = 0, gcEnd = 0, hcPtr = 0;
        bool threw = false;
        __try {
            gcStart = *(uint64_t*)(node + 0x00);
            gcEnd   = *(uint64_t*)(node + 0x08);
            hcPtr   = *(uint64_t*)(node + 0x10);
        } __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }

        if (threw) { LOG("[walk] [%2d] node read threw", idx); break; }

        uint64_t sz = (gcEnd >= gcStart) ? (gcEnd - gcStart + 1) : 0;
        LOG("[walk] [%2d]  GC:%016llX-%016llX  HC:%016llX  %8.2f MB",
            idx,
            (unsigned long long)gcStart,
            (unsigned long long)gcEnd,
            (unsigned long long)hcPtr,
            sz / (1024.0 * 1024.0));

        // HVA translation
        if (TARGET_HVA && hcPtr) {
            if (TARGET_HVA >= hcPtr && TARGET_HVA < hcPtr + sz) {
                laneGPA = gcStart + (TARGET_HVA - hcPtr);
                LOG("[walk]   *** LANE GPA = 0x%016llX ***",
                    (unsigned long long)laneGPA);
            }
        }

        // advance
        uintptr_t next = 0;
        __try { next = *(uintptr_t*)(node + nextOff); }
        __except(EXCEPTION_EXECUTE_HANDLER) { break; }

        node = next;
        idx++;
    }

    LOG("[walk] walked %d nodes", idx);
    return laneGPA;
}

// ── verify lane ───────────────────────────────────────────────────────────────

static void VerifyLaneGPA(Handles* h, RTGCPHYS gpa)
{
    if (gpa == (RTGCPHYS)-1) return;
    int32_t lane = 0xDEAD;
    int rc = -1; bool threw = false;
    __try { rc = g_fnRead(h->pVM, &lane, gpa, 4); }
    __except(EXCEPTION_EXECUTE_HANDLER) { threw = true; }
    LOG("[verify] GPA=%016llX  rc=%d  threw=%d  value=%d",
        (unsigned long long)gpa, rc, (int)threw, lane);
    if (!threw && rc == VINF_SUCCESS && lane >= -1 && lane <= 1)
        LOG("[verify] *** CONFIRMED lane=%d — ready for bot ***", lane);
    else
        LOG("[verify] unexpected — HVA may be stale, do a fresh CE scan");
}

// ── main ──────────────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);
    g_log = fopen(LOG_PATH, "w");
    if (!g_log) { OutputDebugStringA("[recon] fopen failed\n"); return 0; }
    LOG("[recon] v8  TARGET_HVA=0x%016llX", (unsigned long long)TARGET_HVA);

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

    {
        Handles h = ScanForUVM();
        if (!h.valid) { LOG("[recon] no UVM"); goto done; }

        LOG("=== RANGE LIST WALK ===");
        RTGCPHYS laneGPA = WalkRangeList(&h);

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