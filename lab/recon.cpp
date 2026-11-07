/*
 * recon.dll — VirtualBox guest RAM recon
 * Target:  HD-Player.exe (BlueStacks 5+)
 * Compile: x64, MSVC or clang-cl
 * Build:   see bottom of file
 *
 * What it does:
 *   1. Finds BstkVMM.dll in-process
 *   2. Resolves VMR3GetUVM → gets live UVM*
 *   3. Calls PGMR3PhysGetRamRangeCount + PGMR3PhysGetRange
 *      to enumerate every guest RAM region
 *   4. Dumps results to C:\recon_out.txt
 *   5. Does a live read of the lane address you found (optional, see LANE_GPA)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>

// ── types ────────────────────────────────────────────────────────────────────

// Opaque VirtualBox handles — we only need the pointer identity
typedef void* PUVM;
typedef void* PVM;
typedef uint64_t RTGCPHYS;
typedef uintptr_t RTHCUINTPTR;

// Return codes
typedef int32_t VBOXSTRICTRC;
#define VINF_SUCCESS 0

// PGMR3PhysGetRange output struct
// Source: VirtualBox OSE include/VBox/vmm/pgm.h
typedef struct PGMPHYSRANGEINFO {
    RTGCPHYS    GCPhysStart;    // guest physical base of this range
    RTGCPHYS    GCPhysEnd;      // guest physical end (inclusive)
    RTHCUINTPTR HCPtrStart;     // host virtual address of range base (0 if not mapped)
    bool        fHasMapping;    // true if HCPtrStart is valid
} PGMPHYSRANGEINFO;

// ── function pointer types ────────────────────────────────────────────────────

// PUVM VMR3GetUVM(PVM pVM)
// We get PVM from a global — see note below
typedef PUVM   (WINAPI* pfnVMR3GetUVM)(PVM pVM);

// unsigned VMR3GetState(PUVM pUVM) — used to verify VM is running
typedef unsigned (WINAPI* pfnVMR3GetState)(PUVM pUVM);

// uint32_t PGMR3PhysGetRamRangeCount(PUVM pUVM)
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PUVM pUVM);

// int PGMR3PhysGetRange(PUVM pUVM, uint32_t iRange, PGMPHYSRANGEINFO *pInfo)
typedef int (WINAPI* pfnPGMR3PhysGetRange)(PUVM pUVM, uint32_t iRange, PGMPHYSRANGEINFO* pInfo);

// int PGMR3PhysSimpleReadGCPhys(PUVM pUVM, void *pvDst, RTGCPHYS GCPhysSrc, size_t cb)
typedef int (WINAPI* pfnPGMR3PhysSimpleReadGCPhys)(PUVM pUVM, void* pvDst, RTGCPHYS GCPhysSrc, size_t cb);

// int PGMR3PhysSimpleWriteGCPhys(PUVM pUVM, RTGCPHYS GCPhysDst, const void *pvSrc, size_t cb)
typedef int (WINAPI* pfnPGMR3PhysSimpleWriteGCPhys)(PUVM pUVM, RTGCPHYS GCPhysDst, const void* pvSrc, size_t cb);

// ── globals ───────────────────────────────────────────────────────────────────

// Set LANE_GPA to the guest physical address of lane value once we know it.
// Leave as 0 on first run — the dump will tell us the RAM layout.
// After mapping CE's virtual address → guest physical, fill this in and re-run.
#define LANE_GPA  ((RTGCPHYS)0)

static FILE* g_log = nullptr;

#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    char _buf[512]; sprintf_s(_buf, fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(_buf); \
} while(0)

// ── UVM hunting ───────────────────────────────────────────────────────────────
// BlueStacks doesn't expose PVM directly, but VMR3GetUVM is exported and
// BstkVMM.dll keeps a global g_pVM / g_pUVM. We scan BstkVMM.dll's .data
// section for a pointer that, when passed to VMR3GetState, returns a sane value.

static PUVM FindUVM(HMODULE hVMM,
                    pfnVMR3GetState fnGetState,
                    pfnPGMR3PhysGetRamRangeCount fnRangeCount)
{
    // Walk BstkVMM.dll .data looking for a PUVM candidate
    // A live UVM will have PGMR3PhysGetRamRangeCount return > 0
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), hVMM, &mi, sizeof(mi)))
        return nullptr;

    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;
    size_t   size = mi.SizeOfImage;

    // Scan 8-byte aligned pointers in the module's writable sections
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        // Only writable, non-executable sections (.data, .bss)
        DWORD chars = sec->Characteristics;
        if (!(chars & IMAGE_SCN_MEM_WRITE))  continue;
        if (  chars & IMAGE_SCN_MEM_EXECUTE) continue;

        uint8_t* sBase = base + sec->VirtualAddress;
        size_t   sSize = sec->Misc.VirtualSize;

        for (size_t off = 0; off + 8 <= sSize; off += 8) {
            PUVM candidate = *(PUVM*)(sBase + off);
            if (!candidate) continue;
            if ((uintptr_t)candidate < 0x10000) continue; // skip tiny values

            __try {
                uint32_t rc = fnRangeCount(candidate);
                if (rc > 0 && rc < 64) {
                    // Looks like a live UVM
                    unsigned state = fnGetState(candidate);
                    if (state < 16) { // sane state enum value
                        LOG("[recon] UVM candidate at .data+0x%zX → %p (ranges=%u state=%u)",
                            off, candidate, rc, state);
                        return candidate;
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // not a valid pointer, skip
            }
        }
    }
    return nullptr;
}

// ── main recon ────────────────────────────────────────────────────────────────

static DWORD WINAPI ReconThread(LPVOID)
{
    g_log = fopen("X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt", "w");
    LOG("[recon] started, pid=%u", GetCurrentProcessId());

    // 1. Get BstkVMM.dll handle
    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("[recon] BstkVMM.dll not loaded"); goto done; }
    LOG("[recon] BstkVMM.dll base = %p", (void*)hVMM);

    // ── dump all BstkVMM exports ──────────────────────────────────────────────
    {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hVMM;
        IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)hVMM + dos->e_lfanew);
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
            ((uint8_t*)hVMM + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names    = (DWORD*)((uint8_t*)hVMM + exp->AddressOfNames);
        WORD*  ordinals = (WORD*) ((uint8_t*)hVMM + exp->AddressOfNameOrdinals);
        DWORD* funcs    = (DWORD*)((uint8_t*)hVMM + exp->AddressOfFunctions);

        LOG("[exports] total named: %u", exp->NumberOfNames);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* name = (const char*)((uint8_t*)hVMM + names[i]);
            DWORD rva = funcs[ordinals[i]];
            LOG("[export] %s  rva=0x%08X  va=%p", name, rva, (uint8_t*)hVMM + rva);
        }
    }
    // ───────────────────────────────────────────────────────────────────

    // 2. Resolve exports
#define RESOLVE(name, type) \
    auto fn##name = (type)GetProcAddress(hVMM, #name); \
    if (!fn##name) { LOG("[recon] missing export: " #name); goto done; } \
    LOG("[recon] " #name " = %p", (void*)fn##name);

    RESOLVE(VMR3GetState,              pfnVMR3GetState)
    RESOLVE(PGMR3PhysGetRamRangeCount, pfnPGMR3PhysGetRamRangeCount)
    RESOLVE(PGMR3PhysGetRange,         pfnPGMR3PhysGetRange)
    RESOLVE(PGMR3PhysSimpleReadGCPhys, pfnPGMR3PhysSimpleReadGCPhys)
    RESOLVE(PGMR3PhysSimpleWriteGCPhys,pfnPGMR3PhysSimpleWriteGCPhys)
#undef RESOLVE

    // 3. Find live UVM
    LOG("[recon] scanning for live UVM...");
    {
        PUVM uvm = FindUVM(hVMM, fnVMR3GetState, fnPGMR3PhysGetRamRangeCount);
        if (!uvm) { LOG("[recon] UVM not found"); goto done; }
        LOG("[recon] UVM = %p", uvm);

        // 4. Enumerate RAM ranges
        uint32_t nRanges = fnPGMR3PhysGetRamRangeCount(uvm);
        LOG("[recon] RAM ranges: %u", nRanges);
        LOG("[recon] %-4s  %-18s  %-18s  %-18s  %s",
            "idx", "GCPhysStart", "GCPhysEnd", "HCVirtStart", "size(MB)");

        uint64_t totalGuest = 0;
        for (uint32_t i = 0; i < nRanges; i++) {
            PGMPHYSRANGEINFO info = {};
            int rc = fnPGMR3PhysGetRange(uvm, i, &info);
            if (rc != VINF_SUCCESS) {
                LOG("[recon]   range %u: PGMR3PhysGetRange failed rc=%d", i, rc);
                continue;
            }
            uint64_t sz = info.GCPhysEnd - info.GCPhysStart + 1;
            totalGuest += sz;
            LOG("[recon]   [%2u]  GC:%016llX–%016llX  HC:%016llX  %.1f MB%s",
                i,
                (unsigned long long)info.GCPhysStart,
                (unsigned long long)info.GCPhysEnd,
                (unsigned long long)info.HCPtrStart,
                sz / (1024.0 * 1024.0),
                info.fHasMapping ? "" : "  (no HC mapping)");
        }
        LOG("[recon] total guest RAM visible: %.1f MB", totalGuest / (1024.0 * 1024.0));

        // 5. If LANE_GPA is set, do a test read
        if (LANE_GPA != 0) {
            int32_t laneVal = 0;
            int rc = fnPGMR3PhysSimpleReadGCPhys(uvm, &laneVal, LANE_GPA, sizeof(laneVal));
            if (rc == VINF_SUCCESS)
                LOG("[recon] LANE_GPA=0x%llX  value=%d", (unsigned long long)LANE_GPA, laneVal);
            else
                LOG("[recon] LANE_GPA read failed rc=%d", rc);
        }

        LOG("[recon] done. check X:\\Github\\Autonomous Subway\\lab\\logs\\recon_out.txt");
    }

done:
    if (g_log) { fclose(g_log); g_log = nullptr; }
    return 0;
}

// ── DllMain ───────────────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, ReconThread, nullptr, 0, nullptr);
    return TRUE;
}

/*
 * ── BUILD ─────────────────────────────────────────────────────────────────────
 *
 * From VS Developer Command Prompt (x64):
 *
 *   cl /LD /O2 /EHsc /W3 recon.cpp /Fe:recon.dll /link /DLL psapi.lib
 *
 * Or CMakeLists.txt:
 *
 *   add_library(recon SHARED recon.cpp)
 *   target_link_libraries(recon psapi)
 *   set_target_properties(recon PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
 *
 * ── INJECT ────────────────────────────────────────────────────────────────────
 *
 * Use your injector or any standard LoadLibrary injector:
 *
 *   injector.exe --pid <HD-Player PID> --dll recon.dll
 *
 * Then check X:\Github\Autonomous Subway\lab\logs\recon_out.txt for the RAM range dump.
 *
 * ── NEXT STEPS ────────────────────────────────────────────────────────────────
 *
 * 1. Run recon, get the RAM range table.
 * 2. Take the lane address CE gave you (e.g. 0x2BDE7F7335C).
 *    That is an HC (host virtual) address inside HD-Player.exe.
 *    Find which range's HCPtrStart ≤ 0x2BDE7F7335C ≤ HCPtrStart+size.
 *    guest_phys = GCPhysStart + (0x2BDE7F7335C - HCPtrStart)
 * 3. Set LANE_GPA to that guest_phys value and re-inject to verify the read.
 * 4. Once confirmed, we build the real bot dll using PGMR3PhysSimpleReadGCPhys
 *    for state reads and PGMR3PhysSimpleWriteGCPhys for input injection.
 */
