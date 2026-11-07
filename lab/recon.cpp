/*
 * recon.dll v2 — VirtualBox guest RAM recon
 * Target:  HD-Player.exe (BlueStacks 5+)
 * Compile: x64, MSVC or clang-cl
 *
 *   cl /LD /O2 /EHsc recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * Changes from v1:
 *   – ScoreUVM() logs ALL intermediate values for every candidate
 *     (ranges, state, pvm ptr, pvm magic, exception flag)
 *   – Validation bounds relaxed: ranges 1–128, state 0–20
 *   – Score-based selection: best partial match wins even without
 *     full validation, so range table is emitted regardless
 *   – DLL .data section scan added: walks BstkVMM/BstkRT/BstkC/VBoxCAPI
 *     .data and .bss sections for pointer-sized values pointing to
 *     VM_MAGIC — finds the stable global anchor for session restarts
 *   – HVA→GPA translation: once range table is live, maps the known
 *     CE address (TARGET_HVA) to its guest physical address
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

// Host virtual address of lane value from Cheat Engine — stable within session.
// Once we map this to a GPA it becomes session-independent.
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

// ── candidate handle pair ─────────────────────────────────────────────────────

struct VMHandles {
    PVM  pVM;
    PUVM pUVM;
    int  score;   // 0 = no info, higher = more confident
};

// ── UVM scoring ───────────────────────────────────────────────────────────────
//
// Calls all four validation functions and logs every intermediate value.
// Returns a score instead of a bool so we can pick the best partial match.
//
//  +4  PVM magic round-trip:  GetVM(candidate) → non-null → VM_MAGIC match
//  +3  GetVM returns the same PVM we started from (perfect round-trip)
//  +2  ranges in [1, 128]
//  +2  state  in [0, 20]
//  -∞  threw exception → returns -1
//
// Minimum score to trust: 4 (magic round-trip alone is a strong signal).

static int ScoreUVM(PUVM candidate, PVM fromPVM, const char* tag)
{
    if (!candidate || (uintptr_t)candidate < 0x10000) {
        LOG("  [%s] UVM=null or junk ptr, skip", tag);
        return -1;
    }

    uint32_t ranges = 0xDEAD;
    unsigned state  = 0xDEAD;
    PVM      pvm    = nullptr;
    uint32_t magic  = 0;
    bool     threw  = false;

    __try {
        ranges = g_fnRangeCount(candidate);
        state  = g_fnGetState(candidate);
        pvm    = g_fnGetVM(candidate);
        if (pvm && (uintptr_t)pvm >= 0x10000)
            magic = *(uint32_t*)pvm;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        threw = true;
    }

    LOG("  [%s] UVM=%p  ranges=%u  state=%u  pvm=%p  magic=%08X%s",
        tag, candidate, ranges, state, pvm, magic,
        threw ? "  *** EXCEPTION ***" : "");

    if (threw) return -1;

    int score = 0;
    if (pvm && (uintptr_t)pvm >= 0x10000)  score += 1;
    if (magic == VM_MAGIC)                  score += 4;
    if (pvm == fromPVM)                     score += 3;  // perfect round-trip
    if (ranges >= 1 && ranges <= 128)       score += 2;
    if (state  <= 20)                       score += 2;

    LOG("  [%s] score=%d", tag, score);
    return score;
}

// ── VA space scan ─────────────────────────────────────────────────────────────
//
// Scan all committed non-image readable pages for VM_MAGIC.
// For each hit, call VMR3GetUVM and score the result.

static VMHandles ScanVASpace()
{
    VMHandles best = { nullptr, nullptr, -1 };

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;

    uint64_t scanned = 0, hits = 0;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }

        size_t regionSz = mbi.RegionSize;
        bool readable = (mbi.State  == MEM_COMMIT);
        bool hasRead  = (mbi.Protect & 0xFF) != PAGE_NOACCESS &&
                        (mbi.Protect & 0xFF) != PAGE_EXECUTE &&
                        !(mbi.Protect & PAGE_GUARD);
        bool notImage = (mbi.Type != MEM_IMAGE);

        if (readable && hasRead && notImage && regionSz >= 4) {
            scanned += regionSz;
            uint8_t* p    = (uint8_t*)addr;
            uint8_t* pEnd = p + regionSz - 3;

            while (p < pEnd) {
                __try {
                    if (*(uint32_t*)p == VM_MAGIC) {
                        hits++;
                        PVM pvm = (PVM)p;
                        char tag[64];
                        sprintf_s(tag, sizeof(tag), "va-hit#%llu", (unsigned long long)hits);

                        LOG("[vascan] VM_MAGIC @ %p  region=%p  type=%s  protect=%02X",
                            p, mbi.AllocationBase,
                            mbi.Type == MEM_PRIVATE ? "PRIVATE" :
                            mbi.Type == MEM_MAPPED  ? "MAPPED"  : "?",
                            mbi.Protect & 0xFF);

                        PUVM uvm = nullptr;
                        bool getuvmThrew = false;
                        __try { uvm = g_fnGetUVM(pvm); }
                        __except(EXCEPTION_EXECUTE_HANDLER) { getuvmThrew = true; }

                        LOG("  GetUVM(%p) → %p%s", pvm, uvm,
                            getuvmThrew ? " (threw)" : "");

                        int s = ScoreUVM(uvm, pvm, tag);
                        if (s > best.score)
                            best = { pvm, uvm, s };

                        p += 8;
                    } else {
                        p += 4;
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    p += 0x1000;
                }
            }
        }

        addr += regionSz;
    }

    LOG("[vascan] done: %.1f MB scanned, %llu VM_MAGIC hits, best score=%d",
        scanned / (1024.0 * 1024.0), (unsigned long long)hits, best.score);
    return best;
}

// ── DLL .data section scan ────────────────────────────────────────────────────
//
// Walks .data/.bss sections of target DLLs. For each 8-byte aligned value
// that looks like a user-mode pointer, two checks are made:
//
//   Pass A — pointer-to-PVM: does *val == VM_MAGIC?
//             If yes, call GetUVM and score. This finds the stable global
//             that holds a PVM pointer (common pattern in VBox internals).
//
//   Pass B — direct PUVM:    treat val itself as a PUVM candidate and score.
//             This catches DLLs that store the UVM pointer directly.
//
// Even if scoring fails both paths, we log what we find — the DLL name and
// offset give a stable future read target once the PVM is confirmed.

static VMHandles ScanDLLData()
{
    static const char* kDLLs[] = {
        "BstkVMM.dll", "BstkRT.dll", "BstkC.dll",
        "VBoxCAPI.dll", "BstkGuestServices.dll", nullptr
    };

    VMHandles best = { nullptr, nullptr, -1 };

    for (int d = 0; kDLLs[d]; d++) {
        HMODULE hMod = GetModuleHandleA(kDLLs[d]);
        if (!hMod) {
            LOG("[dllscan] %s not loaded", kDLLs[d]);
            continue;
        }

        BYTE* base = (BYTE*)hMod;

        __try {
            IMAGE_DOS_HEADER*   dos = (IMAGE_DOS_HEADER*)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            IMAGE_NT_HEADERS64* nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
            if (nt->Signature  != IMAGE_NT_SIGNATURE)  continue;

            WORD nSec = nt->FileHeader.NumberOfSections;
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

            for (WORD s = 0; s < nSec; s++) {
                char secName[9] = {};
                memcpy(secName, sec[s].Name, 8);

                bool isData = strncmp(secName, ".data", 5) == 0 ||
                              strncmp(secName, ".bss",  4) == 0 ||
                              // some BlueStacks DLLs use non-standard names
                              strncmp(secName, "data",  4) == 0;
                if (!isData) continue;

                DWORD vSize = sec[s].Misc.VirtualSize;
                if (vSize < 8) continue;
                BYTE* start = base + sec[s].VirtualAddress;

                LOG("[dllscan] %s  section='%s'  base=%p  size=0x%X",
                    kDLLs[d], secName, start, vSize);

                uint32_t passAHits = 0, passBHits = 0;

                for (DWORD off = 0; off + 8 <= vSize; off += 8) {
                    __try {
                        uintptr_t val = *(uintptr_t*)(start + off);

                        // coarse plausibility: canonical user-mode pointer
                        if (val < 0x10000 || val > 0x7FFFFFFFFFFFULL) continue;

                        // ── Pass A: pointer-to-PVM ────────────────────────────
                        {
                            uint32_t magic = 0;
                            bool ok = false;
                            __try { magic = *(uint32_t*)val; ok = true; }
                            __except(EXCEPTION_EXECUTE_HANDLER) {}

                            if (ok && magic == VM_MAGIC) {
                                passAHits++;
                                PVM pvm = (PVM)val;
                                PUVM uvm = nullptr;
                                __try { uvm = g_fnGetUVM(pvm); }
                                __except(EXCEPTION_EXECUTE_HANDLER) {}

                                char tag[80];
                                sprintf_s(tag, sizeof(tag), "dll-A:%s+%s+%04X",
                                          kDLLs[d], secName, off);
                                LOG("[dllscan] PVM ptr @ %s+%s+0x%04X → PVM=%p  UVM=%p",
                                    kDLLs[d], secName, off, pvm, uvm);

                                int s2 = ScoreUVM(uvm, pvm, tag);
                                if (s2 > best.score) best = { pvm, uvm, s2 };
                            }
                        }

                        // ── Pass B: val itself as PUVM ────────────────────────
                        // Only score if it passes basic AV sanity; ScoreUVM will
                        // catch exceptions, so this is safe but noisy — only log
                        // hits that score ≥ 4 to avoid log spam.
                        {
                            char tag[80];
                            sprintf_s(tag, sizeof(tag), "dll-B:%s+%s+%04X",
                                      kDLLs[d], secName, off);
                            int s2 = ScoreUVM((PUVM)val, nullptr, tag);
                            if (s2 >= 4) {
                                passBHits++;
                                // GetVM returned the PVM for us inside ScoreUVM;
                                // retrieve it again to store the handle pair.
                                PVM pvm = nullptr;
                                __try { pvm = g_fnGetVM((PUVM)val); }
                                __except(EXCEPTION_EXECUTE_HANDLER) {}
                                LOG("[dllscan] direct UVM @ %s+%s+0x%04X → UVM=%p  PVM=%p",
                                    kDLLs[d], secName, off, (void*)val, pvm);
                                if (s2 > best.score) best = { pvm, (PUVM)val, s2 };
                            }
                        }

                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }

                LOG("[dllscan] %s.%s: passA=%u hits  passB=%u scoring hits",
                    kDLLs[d], secName, passAHits, passBHits);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[dllscan] PE parse threw for %s", kDLLs[d]);
        }
    }

    return best;
}

// ── range table dump ──────────────────────────────────────────────────────────

static void DumpRangeTable(VMHandles* h)
{
    uint32_t nRanges = 0;
    __try { nRanges = g_fnRangeCount(h->pUVM); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[ranges] PGMR3PhysGetRamRangeCount threw");
        return;
    }

    LOG("[ranges] count=%u", nRanges);
    LOG("[ranges] %-4s  %-18s  %-18s  %-18s  %-10s  %s",
        "idx", "GCPhysStart", "GCPhysEnd", "HCVirtStart", "size(MB)", "flags");

    uint64_t total = 0;
    for (uint32_t i = 0; i < nRanges && i < 64; i++) {
        PGMPHYSRANGEINFO info = {};
        int rc = VINF_SUCCESS;
        __try { rc = g_fnGetRange(h->pUVM, i, &info); }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[ranges]   [%2u] threw", i);
            continue;
        }
        if (rc != VINF_SUCCESS) { LOG("[ranges]   [%2u] rc=%d", i, rc); continue; }

        uint64_t sz = info.GCPhysEnd - info.GCPhysStart + 1;
        total += sz;
        LOG("[ranges]   [%2u]  GC:%016llX-%016llX  HC:%016llX  %8.1f MB  %s",
            i,
            (unsigned long long)info.GCPhysStart,
            (unsigned long long)info.GCPhysEnd,
            (unsigned long long)info.HCPtrStart,
            sz / (1024.0 * 1024.0),
            info.fHasMapping ? "mapped" : "NO-HC-MAPPING");
    }
    LOG("[ranges] total guest RAM: %.1f MB", total / (1024.0 * 1024.0));
}

// ── HVA → GPA translation ─────────────────────────────────────────────────────
//
// Walk every mapped range. If the target host virtual address falls within
// [HCPtrStart, HCPtrStart + rangeSize), emit the guest physical address.
// GPA = GCPhysStart + (HVA - HCPtrStart).
//
// Also does a live read of the lane value at that GPA for immediate sanity.

static void TranslateHVA(VMHandles* h, uintptr_t targetHVA)
{
    if (!h->pUVM || !h->pVM) return;

    LOG("[hva2gpa] target HVA = 0x%016llX", (unsigned long long)targetHVA);

    uint32_t nRanges = 0;
    __try { nRanges = g_fnRangeCount(h->pUVM); }
    __except(EXCEPTION_EXECUTE_HANDLER) { LOG("[hva2gpa] RangeCount threw"); return; }

    bool found = false;

    for (uint32_t i = 0; i < nRanges && i < 64; i++) {
        PGMPHYSRANGEINFO info = {};
        int rc = VINF_SUCCESS;
        __try { rc = g_fnGetRange(h->pUVM, i, &info); }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (rc != VINF_SUCCESS || !info.fHasMapping || !info.HCPtrStart) continue;

        uint64_t sz    = info.GCPhysEnd - info.GCPhysStart + 1;
        RTHCUINTPTR lo = info.HCPtrStart;
        RTHCUINTPTR hi = info.HCPtrStart + sz;

        if (targetHVA >= lo && targetHVA < hi) {
            RTGCPHYS gpa = info.GCPhysStart + (RTGCPHYS)(targetHVA - lo);
            LOG("[hva2gpa] *** HIT in range %u ***", i);
            LOG("[hva2gpa]   HVA  0x%016llX", (unsigned long long)targetHVA);
            LOG("[hva2gpa]   GPA  0x%016llX  ← use this in the bot", (unsigned long long)gpa);
            LOG("[hva2gpa]   offset into range: 0x%llX", (unsigned long long)(targetHVA - lo));

            // sanity read — lane value should be -1, 0, or 1
            int32_t laneVal = 0xDEAD;
            int rcRead = VINF_SUCCESS;
            __try { rcRead = g_fnRead(h->pVM, &laneVal, gpa, sizeof(laneVal)); }
            __except(EXCEPTION_EXECUTE_HANDLER) { rcRead = -1; }

            if (rcRead == VINF_SUCCESS)
                LOG("[hva2gpa]   live read: lane=%d  (expect -1/0/1)", laneVal);
            else
                LOG("[hva2gpa]   live read failed rc=%d", rcRead);

            found = true;
        }
    }

    if (!found)
        LOG("[hva2gpa] address not in any mapped range — session HVA may have shifted");
}

// ── main thread ───────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    Sleep(500);

    g_log = fopen(LOG_PATH, "w");
    if (!g_log) {
        OutputDebugStringA("[recon] log open failed\n");
        return 0;
    }

    LOG("[recon] v2  pid=%u", GetCurrentProcessId());

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

        // ── VA space scan ─────────────────────────────────────────────────────
        LOG("=== VA SPACE SCAN ===");
        VMHandles vaResult = ScanVASpace();

        // ── DLL .data scan ────────────────────────────────────────────────────
        LOG("=== DLL DATA SECTION SCAN ===");
        VMHandles dllResult = ScanDLLData();

        // ── pick best across both methods ─────────────────────────────────────
        VMHandles best = (dllResult.score >= vaResult.score) ? dllResult : vaResult;

        LOG("=== SELECTION ===");
        LOG("[select] va  score=%d  PVM=%p  UVM=%p", vaResult.score,  vaResult.pVM,  vaResult.pUVM);
        LOG("[select] dll score=%d  PVM=%p  UVM=%p", dllResult.score, dllResult.pVM, dllResult.pUVM);
        LOG("[select] winner: score=%d  PVM=%p  UVM=%p", best.score, best.pVM, best.pUVM);

        if (best.score < 0 || !best.pUVM) {
            LOG("[recon] no usable UVM found — review candidate scores above");
            goto done;
        }

        if (best.score < 4) {
            LOG("[recon] WARNING: best score=%d is weak — range table may be garbage", best.score);
        }

        // ── range table ───────────────────────────────────────────────────────
        LOG("=== RANGE TABLE ===");
        DumpRangeTable(&best);

        // ── HVA → GPA for the lane value ──────────────────────────────────────
        LOG("=== HVA→GPA for TARGET_HVA=0x%016llX ===", (unsigned long long)TARGET_HVA);
        TranslateHVA(&best, TARGET_HVA);

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