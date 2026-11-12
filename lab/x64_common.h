// x64_common.h — shared x86_64 guest page-table helpers for Android 11 probes.
#pragma once
#include "probe_common.h"
#include <vector>
#include <string>
#include <string.h>

static const uint64_t X64_PHYS_4K = 0x000FFFFFFFFFF000ULL;
static const uint64_t X64_PHYS_2M = 0x000FFFFFFFE00000ULL;
static const uint64_t X64_PHYS_1G = 0x000FFFFFC0000000ULL;
static const uint64_t X64_CHUNK   = 0x100000ULL;

struct GuestRange {
    uint64_t start, end, cb, node;
    char desc[96];
};

static std::vector<GuestRange> g_x64Ranges;
static uint64_t g_x64Ceiling = 0x120000000ULL;

static std::string HostCString(uint64_t ptr, size_t maxlen = 96)
{
    std::string s;
    if (!ptr || !IsCommittedHostPtr(ptr)) return s;
    for (size_t i = 0; i < maxlen; i++) {
        char c = 0;
        if (!SelfRead((uintptr_t)ptr + i, &c, 1)) break;
        if (!c) break;
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) c = '.';
        s += c;
    }
    return s;
}

static std::vector<GuestRange> ReadGuestRanges()
{
    std::vector<GuestRange> out;
    uint64_t node = 0;
    if (!SelfRead64((uintptr_t)g_pVM + 0x1010, &node) || !node) return out;
    for (uint32_t i = 0; node && i < 128; i++) {
        GuestRange r = {};
        r.node = node;
        SelfRead64(node + 0x00, &r.start);
        SelfRead64(node + 0x08, &r.cb);
        SelfRead64(node + 0x28, &r.end);
        uint64_t desc = 0; SelfRead64(node + 0x40, &desc);
        std::string d = HostCString(desc);
        strncpy(r.desc, d.c_str(), sizeof(r.desc) - 1);
        if (r.end < r.start) break;
        out.push_back(r);
        uint64_t next = 0; SelfRead64(node + 0x10, &next);
        if (next == node) break;
        node = next;
    }
    return out;
}

static bool IsRamLike(const GuestRange& r) { return (r.end - r.start + 1) >= 0x100000ULL; }

template <typename Fn>
static void ForEachGuestChunk(const GuestRange& r, Fn fn)
{
    std::vector<uint8_t> buf(X64_CHUNK);
    for (uint64_t pos = r.start; pos <= r.end; ) {
        uint64_t left = r.end - pos + 1;
        size_t want = (size_t)((left < X64_CHUNK) ? left : X64_CHUNK);
        GuestReadRobust(pos, buf.data(), want);
        fn(pos, buf.data(), want);
        pos += want;
    }
}

static std::vector<GuestRange> InitGuestRanges()
{
    std::vector<GuestRange> all = ReadGuestRanges();
    g_x64Ranges.clear();
    for (const auto& r : all)
        if (IsRamLike(r)) g_x64Ranges.push_back(r);
    if (!g_x64Ranges.empty()) g_x64Ceiling = g_x64Ranges.back().end + 1;
    return all;
}

static bool X64Translate(uint64_t cr3, uint64_t gva, uint64_t* out_gpa,
                         std::string* trace = nullptr)
{
    uint64_t pml4e = 0, pdpte = 0, pde = 0, pte = 0;
    uint64_t i4 = (gva >> 39) & 0x1FF;
    uint64_t i3 = (gva >> 30) & 0x1FF;
    uint64_t i2 = (gva >> 21) & 0x1FF;
    uint64_t i1 = (gva >> 12) & 0x1FF;
    if (!GuestReadRobust(cr3 + i4 * 8, &pml4e, 8)) return false;
    if (!(pml4e & 1)) return false;
    uint64_t pdpt = pml4e & X64_PHYS_4K;
    if (!GuestReadRobust(pdpt + i3 * 8, &pdpte, 8)) return false;
    if (!(pdpte & 1)) return false;
    if (pdpte & 0x80) {
        *out_gpa = (pdpte & X64_PHYS_1G) | (gva & 0x3FFFFFFF);
        if (trace) *trace = "1G";
        return true;
    }
    uint64_t pd = pdpte & X64_PHYS_4K;
    if (!GuestReadRobust(pd + i2 * 8, &pde, 8)) return false;
    if (!(pde & 1)) return false;
    if (pde & 0x80) {
        *out_gpa = (pde & X64_PHYS_2M) | (gva & 0x1FFFFF);
        if (trace) *trace = "2M";
        return true;
    }
    uint64_t pt = pde & X64_PHYS_4K;
    if (!GuestReadRobust(pt + i1 * 8, &pte, 8)) return false;
    if (!(pte & 1)) return false;
    *out_gpa = (pte & X64_PHYS_4K) | (gva & 0xFFF);
    if (trace) *trace = "4K";
    return true;
}

static std::string X64ReadString(uint64_t cr3, uint64_t gva, size_t maxlen = 128)
{
    std::string s;
    for (size_t i = 0; i < maxlen; i++) {
        uint64_t gpa = 0;
        if (!X64Translate(cr3, gva + i, &gpa, nullptr)) break;
        char c = 0;
        if (!GuestReadRobust(gpa, &c, 1)) break;
        if (!c) break;
        s += c;
    }
    return s;
}

struct Hit64 { uint64_t loc, entry; };
struct Chain64 {
    uint64_t cr3;
    uint64_t pte_loc;
    uint64_t idx[4];
    bool valid;
};

// Find all present, non-PS table entries whose physical target == child_page.
static std::vector<Hit64> X64FindParents(uint64_t child_page)
{
    std::vector<Hit64> out;
    for (const auto& r : g_x64Ranges) {
        ForEachGuestChunk(r, [&](uint64_t base, uint8_t* buf, size_t len) {
            const uint64_t* q = (const uint64_t*)buf;
            size_t n = len / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t e = q[i];
                if (!(e & 1)) continue;
                if (e & 0x80) continue;
                if ((e & X64_PHYS_4K) != child_page) continue;
                out.push_back({base + (uint64_t)i * 8, e});
            }
        });
    }
    return out;
}

// Sign-extend a 48-bit virtual address into its canonical 64-bit form.
static uint64_t X64CanonicalGva(uint64_t gva)
{
    if (gva & (1ULL << 47)) return gva | 0xFFFF000000000000ULL;
    return gva & 0x0000FFFFFFFFFFFFULL;
}

// Reconstruct the virtual address represented by a chain plus a page offset.
static uint64_t X64GvaFromChain(const Chain64& ch, uint64_t off, bool canonical)
{
    uint64_t g = ((ch.idx[3] & 0x1FF) << 39) | ((ch.idx[2] & 0x1FF) << 30) |
                 ((ch.idx[1] & 0x1FF) << 21) | ((ch.idx[0] & 0x1FF) << 12) |
                 (off & 0xFFF);
    return canonical ? X64CanonicalGva(g) : g;
}

// Enumerate EVERY parent chain from a 4KB leaf PTE, not just the first.
// Kernel/user aliases of the same physical page (e.g. KPTI user PGD vs full
// kernel PGD, or the kernel direct map) produce several chains. False parents
// are possible because the parent search scans all of RAM for a matching
// physical target, so callers must validate each chain by translating back.
static std::vector<Chain64> X64AllChainsFromPte(uint64_t pte_loc, size_t cap = 16)
{
    struct Partial { Chain64 ch; uint64_t table_page; };
    std::vector<Partial> cur;
    Partial p0 = {};
    p0.ch.pte_loc = pte_loc;
    p0.ch.idx[0] = (pte_loc & 0xFFF) / 8;
    p0.table_page = pte_loc & ~0xFFFULL;
    cur.push_back(p0);

    for (int level = 1; level <= 3 && !cur.empty(); level++) {
        std::vector<Partial> next;
        for (const auto& pc : cur) {
            auto parents = X64FindParents(pc.table_page);
            size_t n = 0;
            for (const auto& h : parents) {
                if (n++ >= cap) break;
                Partial np = pc;
                np.ch.idx[level] = (h.loc & 0xFFF) / 8;
                np.table_page = h.loc & ~0xFFFULL;
                next.push_back(np);
            }
        }
        cur.swap(next);
    }

    std::vector<Chain64> out;
    for (const auto& pc : cur) {
        Chain64 c = pc.ch;
        c.cr3 = pc.table_page;
        c.valid = true;
        out.push_back(c);
    }
    return out;
}

// Given a 4KB leaf PTE location, walk parents and return the PML4/CR3 page.
static Chain64 X64ChainFromPte(uint64_t pte_loc)
{
    Chain64 ch = {};
    ch.pte_loc = pte_loc;
    ch.idx[0] = (pte_loc & 0xFFF) / 8;
    uint64_t child = pte_loc & ~0xFFFULL;

    auto l1 = X64FindParents(child);
    if (l1.empty()) return ch;
    ch.idx[1] = (l1.front().loc & 0xFFF) / 8;
    child = l1.front().loc & ~0xFFFULL;

    auto l2 = X64FindParents(child);
    if (l2.empty()) return ch;
    ch.idx[2] = (l2.front().loc & 0xFFF) / 8;
    child = l2.front().loc & ~0xFFFULL;

    auto l3 = X64FindParents(child);
    if (l3.empty()) return ch;
    ch.idx[3] = (l3.front().loc & 0xFFF) / 8;
    ch.cr3 = l3.front().loc & ~0xFFFULL;
    ch.valid = true;
    return ch;
}

static std::string FindSoname(uint64_t* out_hit)
{
    static const char NEEDLE[] = "libil2cpp.so";
    const size_t NL = sizeof(NEEDLE) - 1;
    uint64_t found = 0;
    for (const auto& r : g_x64Ranges) {
        if (found) break;
        ForEachGuestChunk(r, [&](uint64_t base, uint8_t* buf, size_t len) {
            if (found) return;
            for (size_t off = 0; off + NL <= len; off++) {
                if (buf[off] != 'l') continue;
                if (memcmp(buf + off, NEEDLE, NL) != 0) continue;
                if (off > 0 && buf[off - 1] != 0 && buf[off - 1] != '.') continue;
                if (off + NL < len && buf[off + NL] != 0 &&
                    buf[off + NL] != ' ' && buf[off + NL] != '\n') continue;
                found = base + off;
                return;
            }
        });
    }
    if (out_hit) *out_hit = found;
    return found ? "libil2cpp.so" : "";
}

// Find all x86 4K PTEs mapping target_page, and the CR3 that owns them.
static std::vector<uint64_t> FindPtesForPage(uint64_t target_page)
{
    std::vector<uint64_t> out;
    for (const auto& r : g_x64Ranges) {
        ForEachGuestChunk(r, [&](uint64_t base, uint8_t* buf, size_t len) {
            const uint64_t* q = (const uint64_t*)buf;
            size_t n = len / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t e = q[i];
                if (!(e & 1)) continue;
                if (e & 0x80) continue;
                if ((e & X64_PHYS_4K) != target_page) continue;
                out.push_back(base + (uint64_t)i * 8);
            }
        });
    }
    return out;
}

struct Cr3Info { uint64_t cr3, soname_gpa, soname_gva, pte_loc; bool ok; };

static Cr3Info DiscoverCr3()
{
    Cr3Info info = {};
    uint64_t soname_hit = 0;
    if (FindSoname(&soname_hit).empty()) {
        LOG("DiscoverCr3: SONAME not found");
        return info;
    }
    uint64_t page = soname_hit & ~0xFFFULL;
    uint32_t off = (uint32_t)(soname_hit & 0xFFF);
    LOG("DiscoverCr3: SONAME GPA=%016llX page=%016llX off=0x%X",
        (unsigned long long)soname_hit, (unsigned long long)page, off);

    auto ptes = FindPtesForPage(page);
    LOG("DiscoverCr3: %zu PTE candidates", ptes.size());
    for (uint64_t pte : ptes) {
        Chain64 ch = X64ChainFromPte(pte);
        if (!ch.valid) continue;
        uint64_t gva = (ch.idx[3] << 39) | (ch.idx[2] << 30) |
                       (ch.idx[1] << 21) | (ch.idx[0] << 12) | off;
        uint64_t gpa = 0;
        std::string tr;
        if (!X64Translate(ch.cr3, gva, &gpa, &tr)) continue;
        if ((gpa & ~0xFFFULL) != page) continue;
        std::string s = X64ReadString(ch.cr3, gva, 32);
        LOG("  CR3=%016llX GVA=%016llX -> GPA=%016llX str=\"%s\"",
            (unsigned long long)ch.cr3, (unsigned long long)gva,
            (unsigned long long)gpa, s.c_str());
        if (s.compare(0, 12, "libil2cpp.so") == 0) {
            info.cr3 = ch.cr3;
            info.soname_gpa = soname_hit;
            info.soname_gva = gva;
            info.pte_loc = pte;
            info.ok = true;
            return info;
        }
    }
    LOG("DiscoverCr3: no verified CR3");
    return info;
}

// Reverse-map a GPA to the GVA that the given CR3 uses. Works for 4K PTEs and
// 2M PDEs. Scans page tables; used for the class struct and lane GPAs.
static bool X64GpaToGva(uint64_t cr3, uint64_t gpa, uint64_t* out_gva)
{
    uint64_t page = gpa & ~0xFFFULL;
    uint64_t off  = gpa & 0xFFFULL;

    // 4K leaf
    auto ptes = FindPtesForPage(page);
    for (uint64_t pte : ptes) {
        Chain64 ch = X64ChainFromPte(pte);
        if (!ch.valid || ch.cr3 != cr3) continue;
        uint64_t gva = (ch.idx[3] << 39) | (ch.idx[2] << 30) |
                       (ch.idx[1] << 21) | (ch.idx[0] << 12) | off;
        uint64_t chk = 0;
        if (X64Translate(cr3, gva, &chk, nullptr) && (chk & ~0xFFFULL) == page) {
            if (out_gva) *out_gva = gva;
            return true;
        }
    }

    // 2M huge leaf: find a PDE with PS=1 whose block contains gpa.
    uint64_t block = gpa & X64_PHYS_2M;
    for (const auto& r : g_x64Ranges) {
        ForEachGuestChunk(r, [&](uint64_t base, uint8_t* buf, size_t len) {
            const uint64_t* q = (const uint64_t*)buf;
            size_t n = len / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t e = q[i];
                if (!(e & 1) || !(e & 0x80)) continue;
                if ((e & X64_PHYS_2M) != block) continue;
                uint64_t pde_loc = base + (uint64_t)i * 8;
                uint64_t idx2 = (pde_loc & 0xFFF) / 8;
                uint64_t child = pde_loc & ~0xFFFULL;
                auto l1 = X64FindParents(child);
                if (l1.empty()) continue;
                uint64_t idx3 = (l1.front().loc & 0xFFF) / 8;
                uint64_t child2 = l1.front().loc & ~0xFFFULL;
                auto l2 = X64FindParents(child2);
                if (l2.empty()) continue;
                uint64_t idx4 = (l2.front().loc & 0xFFF) / 8;
                uint64_t root = l2.front().loc & ~0xFFFULL;
                if (root != cr3) continue;
                uint64_t gva = (idx4 << 39) | (idx3 << 30) | (idx2 << 21) |
                               (gpa & 0x1FFFFFULL);
                uint64_t chk = 0;
                if (X64Translate(cr3, gva, &chk, nullptr) &&
                    (chk & X64_PHYS_2M) == block) {
                    if (out_gva) *out_gva = gva;
                    return true;
                }
            }
        });
    }
    return false;
}
