// Shared bridge/probe helpers. MinGW-safe: no SEH, all host reads go through
// ReadProcessMemory on our own process so bad addresses return false instead
// of raising an access violation.
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef void*     PUVM;
typedef void*     PVM;
typedef uint64_t  RTGCPHYS;

typedef void*    (WINAPI* pfnVMR3GetUVM)               (PVM);
typedef void*    (WINAPI* pfnVMR3GetVM)                (PUVM);
typedef uint32_t (WINAPI* pfnPGMR3PhysGetRamRangeCount)(PVM);
typedef int      (WINAPI* pfnPGMPhysSimpleReadGCPhys)  (PVM, void*, RTGCPHYS, size_t);
typedef int      (WINAPI* pfnPGMPhysSimpleWriteGCPhys) (PVM, RTGCPHYS, const void*, size_t);

static const uint32_t UVM_MAGIC = 0x19700823;

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

static pfnVMR3GetUVM                g_fnGetUVM;
static pfnVMR3GetVM                 g_fnGetVM;
static pfnPGMR3PhysGetRamRangeCount g_fnRangeCount;
static pfnPGMPhysSimpleReadGCPhys   g_fnRead;
static pfnPGMPhysSimpleWriteGCPhys  g_fnWrite;

static FILE*    g_log     = nullptr;
static void*    g_pVM     = nullptr;
static PUVM     g_pUVM    = nullptr;
static uint64_t g_hvaBase = 0;
static uint32_t g_nRanges = 0;

#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    char _b[1024]; \
    snprintf(_b, sizeof(_b), "[probe] " fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(_b); \
} while (0)

static bool SelfRead(uintptr_t addr, void* dst, size_t cb)
{
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, dst, cb, &got)) return false;
    return got == cb;
}

static bool SelfRead64(uintptr_t addr, uint64_t* out) { return SelfRead(addr, out, 8); }
static bool SelfRead32(uintptr_t addr, uint32_t* out) { return SelfRead(addr, out, 4); }

static bool IsCommittedHostPtr(uint64_t v)
{
    if (!v) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery((LPCVOID)(uintptr_t)v, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

static bool GuestRead(RTGCPHYS gpa, void* dst, size_t cb)
{
    if (!g_fnRead || !g_pVM) return false;
    int rc = -1;
    rc = g_fnRead(g_pVM, dst, gpa, cb);
    return rc == 0;
}

static bool GuestRead64(RTGCPHYS gpa, uint64_t* out) { return GuestRead(gpa, out, 8); }
static bool GuestRead32(RTGCPHYS gpa, uint32_t* out) { return GuestRead(gpa, out, 4); }

// Large PGMPhysSimpleReadGCPhys calls can fail when the requested span crosses
// a mapping/chunk boundary. Fall back to 4 KB page reads so a bad chunk only
// skips the pages that are genuinely unreadable.
static bool GuestReadRobust(RTGCPHYS gpa, void* dst, size_t cb)
{
    if (GuestRead(gpa, dst, cb)) return true;
    uint8_t* p = (uint8_t*)dst;
    for (size_t d64 = 0; d64 < cb; d64 += 0x10000) {
        size_t n64 = cb - d64;
        if (n64 > 0x10000) n64 = 0x10000;
        if (GuestRead(gpa + d64, p + d64, n64)) continue;
        for (size_t d4 = 0; d4 < n64; d4 += 0x1000) {
            size_t n4 = n64 - d4;
            if (n4 > 0x1000) n4 = 0x1000;
            if (!GuestRead(gpa + d64 + d4, p + d64 + d4, n4))
                memset(p + d64 + d4, 0, n4);
        }
    }
    return true;
}

// Read one qword from the host at an arbitrary address, logging only the value.
static void LogQword(uintptr_t addr, const char* label)
{
    uint64_t v = 0;
    if (!SelfRead64(addr, &v)) {
        LOG("  %s @ %016llX  <unreadable>", label, (unsigned long long)addr);
        return;
    }
    char ann[256] = "";
    if (v == 0) {
        strcpy(ann, "zero");
    } else if (IsCommittedHostPtr(v)) {
        MEMORY_BASIC_INFORMATION mbi = {};
        VirtualQuery((LPCVOID)(uintptr_t)v, &mbi, sizeof(mbi));
        snprintf(ann, sizeof(ann), "HOSTPTR region=%p base=%p size=%llX type=%lu prot=%lX",
                 (void*)(uintptr_t)v, mbi.BaseAddress,
                 (unsigned long long)mbi.RegionSize, (unsigned long)mbi.Type,
                 (unsigned long)mbi.Protect);
    }
    LOG("  %s @ %016llX  %016llX  %s", label, (unsigned long long)addr,
        (unsigned long long)v, ann);
}

static bool InitVBoxBridge()
{
    HMODULE hVMM = GetModuleHandleA("BstkVMM.dll");
    if (!hVMM) { LOG("BstkVMM.dll not loaded"); return false; }
    LOG("BstkVMM.dll base=%p", (void*)hVMM);

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

    LOG("UVM scan: %p .. %p", (void*)addr, (void*)end);
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
                uint32_t magic = 0;
                if (SelfRead32(pg, &magic) && magic == UVM_MAGIC) {
                    uint64_t pvm64 = 0;
                    if (SelfRead64(pg + 8, &pvm64) && pvm64) {
                        void* pvm = (void*)(uintptr_t)pvm64;
                        void* gotPVM = nullptr; PUVM gotUVM = nullptr;
                        gotPVM = g_fnGetVM((PUVM)pg);
                        gotUVM = g_fnGetUVM(pvm);
                        if (gotPVM == pvm && gotUVM == (PUVM)pg) {
                            uint32_t rc = g_fnRangeCount((PVM)pvm);
                            if (rc >= 1 && rc <= 512) {
                                g_pUVM = (PUVM)pg;
                                g_pVM  = pvm;
                                g_nRanges = rc;
                                LOG("UVM FOUND: pUVM=%p pVM=%p nRanges=%u (scan region %p+%llX)",
                                    (void*)pg, pvm, rc, mbi.BaseAddress,
                                    (unsigned long long)mbi.RegionSize);
                                return true;
                            }
                        }
                    }
                }
                pg += 0x1000;
            }
        }
        addr += rSize;
    }
    LOG("UVM scan failed");
    return false;
}

static bool LooksLikeRange(uintptr_t addr, uint64_t* out_start, uint64_t* out_end,
                           uint64_t* out_hc, uint64_t* out_next)
{
    uint64_t s = 0, e = 0, hc = 0, nx = 0;
    if (!SelfRead64(addr + 0x00, &s)) return false;
    if (!SelfRead64(addr + 0x08, &e)) return false;
    if (!SelfRead64(addr + 0x10, &hc)) return false;
    if (s > e) return false;
    if (s > 0x10000000000ULL || e > 0x10000000000ULL) return false;
    uint64_t span = e - s;
    if (span < 0x1000 || span > 0x10000000000ULL) return false;
    if (s & 0xFFF) return false;
    // Some VBox versions store GCPhysLast inclusive, others exclusive.
    if ((e & 0xFFF) && ((e + 1) & 0xFFF)) return false;
    if (!IsCommittedHostPtr(hc)) return false;
    if (out_start) *out_start = s;
    if (out_end)   *out_end   = e;
    if (out_hc)    *out_hc    = hc;
    if (out_next)  *out_next  = nx;
    return true;
}

static void DumpRangeNode(uintptr_t addr, const char* label, uint32_t qwords)
{
    LOG("--- %s node @ %016llX (first %u qwords) ---", label,
        (unsigned long long)addr, qwords);
    for (uint32_t i = 0; i < qwords; i++) {
        uint64_t v = 0;
        uintptr_t a = addr + (uintptr_t)i * 8;
        if (!SelfRead64(a, &v)) { LOG("  +%04X  <unreadable>", i * 8); continue; }
        char ann[256] = "";
        if (v == 0) strcpy(ann, "zero");
        else if (IsCommittedHostPtr(v)) {
            MEMORY_BASIC_INFORMATION mbi = {};
            VirtualQuery((LPCVOID)(uintptr_t)v, &mbi, sizeof(mbi));
            snprintf(ann, sizeof(ann), "HOSTPTR region=%p+%llX prot=%lX type=%lu",
                     mbi.BaseAddress, (unsigned long long)mbi.RegionSize,
                     (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
        } else if (v < 0x10000000000ULL) {
            snprintf(ann, sizeof(ann), "(small int 0x%llX)", (unsigned long long)v);
        }
        LOG("  +%04X  %016llX  %s", i * 8, (unsigned long long)v, ann);
    }
}

static void DumpQwords(const char* label, uintptr_t base, uint32_t count)
{
    LOG("--- %s @ %016llX (%u qwords) ---", label,
        (unsigned long long)base, count);
    for (uint32_t i = 0; i < count; i++) {
        uintptr_t a = base + (uintptr_t)i * 8;
        uint64_t v = 0;
        if (!SelfRead64(a, &v)) { LOG("  +%04X  <unreadable>", i * 8); continue; }
        char ann[128] = "";
        if (v == 0) strcpy(ann, "zero");
        else if (IsCommittedHostPtr(v)) strcpy(ann, "HOSTPTR");
        LOG("  +%04X  %016llX  %s", i * 8, (unsigned long long)v, ann);
    }
}
