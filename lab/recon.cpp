/*
 * recon_android11.cpp — guest-RAM lane reader for BlueStacks 5 / Android 11
 *
 * Six-stage pipeline (all self-discovered; no hard-coded session addresses):
 *
 *   STAGE 1  VBox VMM bridge      BstkVMM.dll exports + UVM discovery
 *   STAGE 2  guest RAM range map  PGM RAM-range list (corrected Android 11 layout)
 *   STAGE 3  game address space   find "libil2cpp.so" in guest RAM and collect
 *                                 the x86_64 CR3s that map it (batched parent
 *                                 chain reconstruction)
 *   STAGE 4  metadata + classes   locate the global-metadata header page in a
 *                                 candidate CR3, derive the metadata base GVA
 *                                 (virtual contiguity is verified with the
 *                                 CharacterMotor / LaneStateInfo strings), then
 *                                 find the Il2CppClass objects by name pointer
 *   STAGE 5  player motor         strict CharacterMotor instance validation
 *                                 (monitor==0, lane in range, bools, velocity)
 *                                 and pick the input-driven player motor
 *   STAGE 6  lane streaming       \\.\pipe\recon  LANE -1/0/1
 *
 * Field offsets are read from the live FieldInfo arrays by name, so this is
 * not tied to the verified fallback constants (kept for diagnostics only).
 *
 * Pipe protocol (unchanged from recon.cpp v12):
 *   SET_GPA <hex>\n   override the lane GPA       -> OK | ERR
 *   READ\n            read the current lane       -> LANE <n> | LANE ? | ERR
 *   START\n           stream LANE lines on change -> OK, then LANE lines
 *   STOP\n            stop streaming              -> OK
 *   PING\n                                        -> PONG
 *   banner: STATUS READY HVA_BASE <hex>
 *
 * Injected once per BlueStacks session.  DLL_PROCESS_DETACH is intentionally
 * ignored: unloading this DLL corrupts VMM state.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <atomic>
#include <algorithm>

#include "x64_common.h"

#define LOG_PATH  "X:\\Github\\Programmatic Control\\logs\\recon_android11.txt"
#define PIPE_NAME "\\\\.\\pipe\\recon"

// global-metadata.dat v31 offsets (verified against the live APK metadata)
static const uint64_t OFF_CM_NAME  = 0xE54E1ULL;   // "CharacterMotor"
static const uint64_t OFF_CM_F0    = 0xE5FA8ULL;   // "MinimalVerticalSpeed"
static const uint64_t OFF_LSI_NAME = 0xE649FULL;   // "LaneStateInfo"
static const uint64_t OFF_LSI_F0   = 0xE629CULL;   // "IsChangingLane"

// Verified fallbacks for this build.  Runtime discovery is preferred.
static const uint32_t FB_LANE_STATE  = 0x108;
static const uint32_t FB_CONTROLLER  = 0xC0;
static const uint32_t FB_CURRENT_ST  = 0x1A8;
static const uint32_t FB_ALLOW_INPUT = 0x1D0;
static const uint32_t FB_VELOCITY    = 0x1D4;
static const uint32_t FB_IS_ACTIVE   = 0x1E8;
static const uint32_t FB_ACCELERATE  = 0x1EA;
// Verified live by probe 29: the inline LaneStateInfo struct starts at
// CharacterMotor+0x108 and its first field is IsChangingLane (bool), with
// TargetLane at +0x14 (so TargetLane sits at object+0x11C).  Values are
// -1 / 0 / 1 for left / centre / right.
static const uint32_t FB_TARGET_LANE = 0x14;
static const uint32_t FB_CHANGING    = 0x00;

// ─────────────────────────────────────────────────────────────────────────────
// Shared state
// ─────────────────────────────────────────────────────────────────────────────
static std::atomic<bool>     g_bridgeReady { false };
static std::atomic<bool>     g_streaming   { false };
static std::atomic<bool>     g_useUserGpa  { false };
static std::atomic<uint64_t> g_userGpa     { 0 };
static std::atomic<uint64_t> g_autoLaneGpa { 0 };
static std::atomic<uint64_t> g_motorGpa    { 0 };

struct ClassInfo {
    uint64_t gpa = 0;
    uint64_t fields_gpa = 0;
    uint64_t name_ptr = 0;
    uint32_t fc = 0;
    bool ok = false;
};

struct MetaCandidate { uint64_t cr3 = 0, base = 0; };

static std::vector<uint64_t> g_cr3s;              // candidate game CR3s
static std::vector<MetaCandidate> g_metas;        // validated metadata bases
static uint64_t g_cr3 = 0;                        // selected game CR3
static uint64_t g_metaBase = 0;
static uint64_t g_metaCr3 = 0;
static std::vector<uint64_t> g_magicGpas;
static std::set<uint64_t> g_cmClassPtrs;
static ClassInfo g_cm;
static ClassInfo g_lsi;

static uint32_t offLaneState = FB_LANE_STATE;
static uint32_t offController = FB_CONTROLLER;
static uint32_t offCurrentState = FB_CURRENT_ST;
static uint32_t offAllowInput = FB_ALLOW_INPUT;
static uint32_t offVelocity = FB_VELOCITY;
static uint32_t offIsActive = FB_IS_ACTIVE;
static uint32_t offAccelerate = FB_ACCELERATE;
static uint32_t offTargetLane = FB_TARGET_LANE;
static uint32_t offChanging = FB_CHANGING;

// ─────────────────────────────────────────────────────────────────────────────
// Guest RAM scanning
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint64_t> FindStringHitsN(const char* needle, size_t nl,
                                             size_t cap)
{
    std::vector<uint64_t> out;
    if (!nl) return out;
    std::vector<uint8_t> buf(X64_CHUNK + 64);
    for (const auto& r : g_x64Ranges) {
        for (uint64_t pos = r.start; pos <= r.end; ) {
            uint64_t left = r.end - pos + 1;
            size_t n = (size_t)((left < X64_CHUNK) ? left : X64_CHUNK);
            size_t n2 = (size_t)((left < (uint64_t)(X64_CHUNK + 64)) ? left
                                                                    : (uint64_t)(X64_CHUNK + 64));
            GuestReadRobust(pos, buf.data(), n2);
            for (size_t off = 0; off < n && off + nl <= n2; off++) {
                if (buf[off] != (uint8_t)needle[0]) continue;
                if (memcmp(buf.data() + off, needle, nl) != 0) continue;
                out.push_back(pos + off);
                if (cap && out.size() >= cap) return out;
            }
            pos += n;
        }
    }
    return out;
}

static std::vector<uint64_t> FindMetaMagicGpas()
{
    static const uint8_t MAGIC[8] = { 0xAF, 0x1B, 0xB1, 0xFA, 0x1F, 0, 0, 0 };
    std::vector<uint64_t> out;
    std::vector<uint8_t> buf(X64_CHUNK);
    for (const auto& r : g_x64Ranges) {
        for (uint64_t pos = r.start; pos <= r.end; ) {
            uint64_t left = r.end - pos + 1;
            size_t n = (size_t)((left < X64_CHUNK) ? left : X64_CHUNK);
            GuestReadRobust(pos, buf.data(), n);
            for (size_t off = 0; off + 8 <= n; off++)
                if (!memcmp(buf.data() + off, MAGIC, 8)) {
                    out.push_back(pos + off);
                    if (out.size() >= 8) return out;
                }
            pos += n;
        }
    }
    return out;
}

static uint64_t FindMetaMagicGpa() { auto v = FindMetaMagicGpas(); return v.empty() ? 0 : v[0]; }

static std::vector<uint64_t> FindQwordsAny(const std::set<uint64_t>& values,
                                           size_t cap = 4096)
{
    std::vector<uint64_t> out;
    uint64_t vmin = UINT64_MAX, vmax = 0;
    for (uint64_t v : values) { vmin = std::min(vmin, v); vmax = std::max(vmax, v); }
    std::vector<uint8_t> buf(X64_CHUNK);
    for (const auto& r : g_x64Ranges) {
        for (uint64_t pos = r.start; pos <= r.end; ) {
            uint64_t left = r.end - pos + 1;
            size_t n = (size_t)((left < X64_CHUNK) ? left : X64_CHUNK);
            GuestReadRobust(pos, buf.data(), n);
            const uint64_t* q = (const uint64_t*)buf.data();
            for (size_t i = 0; i < n / 8; i++) {
                uint64_t v = q[i];
                if (v < vmin || v > vmax) continue;
                if (!values.count(v)) continue;
                out.push_back(pos + (uint64_t)i * 8);
                if (cap && out.size() >= cap) return out;
            }
            pos += n;
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Batched page-table chain reconstruction
// ─────────────────────────────────────────────────────────────────────────────
struct EntryHit { uint64_t child; uint64_t loc; };

static std::vector<EntryHit> FindParentEntries(const std::set<uint64_t>& childPages)
{
    std::vector<EntryHit> out;
    if (childPages.empty()) return out;
    std::vector<uint8_t> buf(X64_CHUNK);
    for (const auto& r : g_x64Ranges) {
        for (uint64_t pos = r.start; pos <= r.end; ) {
            uint64_t left = r.end - pos + 1;
            size_t n = (size_t)((left < X64_CHUNK) ? left : X64_CHUNK);
            GuestReadRobust(pos, buf.data(), n);
            const uint64_t* q = (const uint64_t*)buf.data();
            for (size_t i = 0; i < n / 8; i++) {
                uint64_t e = q[i];
                if (!(e & 1) || (e & 0x80)) continue;
                uint64_t frame = e & X64_PHYS_4K;
                if (!childPages.count(frame)) continue;
                out.push_back({ frame, pos + (uint64_t)i * 8 });
            }
            pos += n;
        }
    }
    return out;
}

struct LeafRef { uint64_t frame; uint64_t off; };
struct ChainRef { uint64_t cr3; uint64_t gva; };

static std::vector<ChainRef> ChainsForLeaves(const std::vector<LeafRef>& leaves,
                                             size_t cap = 16384)
{
    std::vector<ChainRef> out;
    std::set<uint64_t> frames;
    for (const auto& l : leaves) frames.insert(l.frame);
    auto ptes = FindParentEntries(frames);
    if (ptes.empty()) return out;

    struct Partial { uint64_t idx[4]; uint64_t page; uint64_t frame; uint64_t off; };
    std::vector<Partial> cur;
    for (const auto& e : ptes)
        for (const auto& l : leaves) {
            if (l.frame != e.child) continue;
            Partial p = {};
            p.idx[0] = (e.loc & 0xFFF) / 8;
            p.page = e.loc & ~0xFFFULL;
            p.frame = l.frame;
            p.off = l.off;
            cur.push_back(p);
        }

    for (int level = 1; level <= 3 && !cur.empty(); level++) {
        std::set<uint64_t> pages;
        for (const auto& p : cur) pages.insert(p.page);
        auto parents = FindParentEntries(pages);
        if (parents.empty()) { cur.clear(); break; }
        std::map<uint64_t, std::vector<uint64_t>> byChild;
        for (const auto& e : parents) byChild[e.child].push_back(e.loc);
        std::vector<Partial> next;
        for (const auto& p : cur) {
            auto it = byChild.find(p.page);
            if (it == byChild.end()) continue;
            for (uint64_t loc : it->second) {
                Partial np = p;
                np.idx[level] = (loc & 0xFFF) / 8;
                np.page = loc & ~0xFFFULL;
                next.push_back(np);
                if (next.size() >= cap) break;
            }
            if (next.size() >= cap) break;
        }
        cur.swap(next);
    }

    std::set<std::pair<uint64_t, uint64_t>> seen;
    for (const auto& p : cur) {
        uint64_t gva = ((p.idx[3] & 0x1FF) << 39) | ((p.idx[2] & 0x1FF) << 30) |
                       ((p.idx[1] & 0x1FF) << 21) | ((p.idx[0] & 0x1FF) << 12) |
                       (p.off & 0xFFF);
        if (!seen.insert({p.page, gva}).second) continue;
        uint64_t chk = 0;
        if (!X64Translate(p.page, gva, &chk, nullptr)) continue;
        if ((chk & ~0xFFFULL) != p.frame) continue;
        out.push_back({ p.page, gva });
    }
    return out;
}

// Forward walk of one CR3: every GVA (page base) mapping any target page.
static std::map<uint64_t, std::vector<uint64_t>>
WalkCr3ForPages(uint64_t cr3, const std::set<uint64_t>& pages)
{
    std::map<uint64_t, std::vector<uint64_t>> out;
    std::set<uint64_t> p2m, p1g;
    for (uint64_t p : pages) { p2m.insert(p & X64_PHYS_2M); p1g.insert(p & X64_PHYS_1G); }
    for (uint64_t i4 = 0; i4 < 512; i4++) {
        uint64_t e4 = 0;
        if (!GuestRead64(cr3 + i4 * 8, &e4) || !(e4 & 1)) continue;
        uint64_t pdpt = e4 & X64_PHYS_4K;
        for (uint64_t i3 = 0; i3 < 512; i3++) {
            uint64_t e3 = 0;
            if (!GuestRead64(pdpt + i3 * 8, &e3) || !(e3 & 1)) continue;
            if (e3 & 0x80) {
                uint64_t blk = e3 & X64_PHYS_1G;
                if (!p1g.count(blk)) continue;
                for (uint64_t p : pages)
                    if ((p & X64_PHYS_1G) == blk)
                        out[p].push_back((i4 << 39) | (i3 << 30) | (p & 0x3FFFFFFFULL));
                continue;
            }
            uint64_t pd = e3 & X64_PHYS_4K;
            for (uint64_t i2 = 0; i2 < 512; i2++) {
                uint64_t e2 = 0;
                if (!GuestRead64(pd + i2 * 8, &e2) || !(e2 & 1)) continue;
                if (e2 & 0x80) {
                    uint64_t blk = e2 & X64_PHYS_2M;
                    if (!p2m.count(blk)) continue;
                    for (uint64_t p : pages)
                        if ((p & X64_PHYS_2M) == blk)
                            out[p].push_back((i4 << 39) | (i3 << 30) | (i2 << 21) |
                                             (p & 0x1FFFFFULL));
                    continue;
                }
                uint64_t pt = e2 & X64_PHYS_4K;
                for (uint64_t i1 = 0; i1 < 512; i1++) {
                    uint64_t e1 = 0;
                    if (!GuestRead64(pt + i1 * 8, &e1) || !(e1 & 1)) continue;
                    uint64_t frame = e1 & X64_PHYS_4K;
                    if (!pages.count(frame)) continue;
                    out[frame].push_back((i4 << 39) | (i3 << 30) | (i2 << 21) | (i1 << 12));
                }
            }
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 1/2 — bridge + corrected Android 11 range map
// ─────────────────────────────────────────────────────────────────────────────
static bool Stage1Bridge()
{
    LOG("=== STAGE 1: VBox VMM bridge ===");
    if (!InitVBoxBridge()) { LOG("bridge: BstkVMM exports missing"); return false; }
    if (!ScanForUVM())     { LOG("bridge: UVM not found"); return false; }
    LOG("bridge ready: pVM=%p ranges=%u", g_pVM, g_nRanges);
    return true;
}

static bool Stage2Ranges()
{
    LOG("=== STAGE 2: guest RAM range map ===");
    std::vector<GuestRange> all = ReadGuestRanges();
    g_x64Ranges.clear();
    for (const auto& r : all) {
        LOG("  range %016llX-%016llX %6llu MB  %s",
            (unsigned long long)r.start, (unsigned long long)r.end,
            (unsigned long long)((r.end - r.start + 1) >> 20), r.desc);
        if (r.end - r.start + 1 >= 0x100000ULL)
            g_x64Ranges.push_back(r);
    }
    if (g_x64Ranges.empty()) { LOG("range map: no RAM-like ranges"); return false; }
    g_x64Ceiling = g_x64Ranges.back().end + 1;
    uint64_t total = 0;
    for (const auto& r : g_x64Ranges) total += r.end - r.start + 1;
    LOG("range map: %zu RAM ranges, %llu MB, ceiling %016llX",
        g_x64Ranges.size(), (unsigned long long)(total >> 20),
        (unsigned long long)g_x64Ceiling);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 3 — candidate game address spaces (CR3s mapping libil2cpp.so)
// ─────────────────────────────────────────────────────────────────────────────
static bool Stage3Cr3s()
{
    LOG("=== STAGE 3: game address spaces ===");
    static const char NEEDLE[] = "libil2cpp.so";
    size_t nl = sizeof(NEEDLE);   // includes the NUL terminator
    auto hits = FindStringHitsN(NEEDLE, nl, 1024);
    LOG("stage 3: %zu exact \"libil2cpp.so\" strings", hits.size());
    if (hits.empty()) return false;

    std::vector<LeafRef> leaves;
    for (uint64_t p : hits) leaves.push_back({ p & ~0xFFFULL, p & 0xFFF });

    auto chains = ChainsForLeaves(leaves, 32768);
    LOG("stage 3: %zu candidate (cr3,gva) mappings", chains.size());

    std::set<uint64_t> cr3s;
    for (const auto& c : chains) {
        if (X64ReadString(c.cr3, c.gva, 16) != "libil2cpp.so") continue;
        cr3s.insert(c.cr3);
    }
    g_cr3s.assign(cr3s.begin(), cr3s.end());
    LOG("stage 3: %zu distinct CR3s map the soname", g_cr3s.size());
    for (uint64_t c : g_cr3s)
        LOG("  CR3=%016llX", (unsigned long long)c);
    return !g_cr3s.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 4 — metadata base + il2cpp classes
// ─────────────────────────────────────────────────────────────────────────────
static std::string ClassNameAt(uint64_t cr3, uint64_t gva)
{
    uint64_t gpa = 0;
    if (!gva || !X64Translate(cr3, gva, &gpa, nullptr)) return "";
    uint64_t klass = 0;
    if (!GuestRead64(gpa, &klass) || !klass) return "";
    uint64_t kgpa = 0;
    if (!X64Translate(cr3, klass, &kgpa, nullptr)) return "";
    uint64_t name = 0;
    GuestRead64(kgpa + 0x10, &name);
    return X64ReadString(cr3, name, 64);
}

static uint32_t FindFieldOffsetByName(uint64_t cr3, const ClassInfo& ci,
                                      const char* name, uint32_t fallback)
{
    if (!ci.fields_gpa) return fallback;   // FieldInfo array paged out
    for (uint32_t i = 0; i < ci.fc; i++) {
        uint64_t nm = 0;
        if (!GuestRead64(ci.fields_gpa + (uint64_t)i * 0x20, &nm)) break;
        if (X64ReadString(cr3, nm, 64) == name) {
            uint32_t off = 0;
            GuestRead32(ci.fields_gpa + (uint64_t)i * 0x20 + 0x18, &off);
            return off;
        }
    }
    return fallback;
}

static int FindFieldIndexByName(uint64_t cr3, const ClassInfo& ci, const char* name)
{
    if (!ci.fields_gpa) return -1;
    for (uint32_t i = 0; i < ci.fc; i++) {
        uint64_t nm = 0;
        if (!GuestRead64(ci.fields_gpa + (uint64_t)i * 0x20, &nm)) break;
        if (X64ReadString(cr3, nm, 64) == name) return (int)i;
    }
    return -1;
}

// Load an Il2CppClass given its guest-physical address (no name validation).
static bool LoadClassAt(uint64_t cr3, uint64_t clsGpa, ClassInfo* out)
{
    uint64_t name = 0, fields = 0, fgpa = 0;
    uint16_t fc = 0;
    GuestRead64(clsGpa + 0x10, &name);
    GuestRead64(clsGpa + 0x80, &fields);
    GuestRead(clsGpa + 0x124, &fc, 2);
    if (!name || !fields || !fc) return false;
    if (!X64Translate(cr3, fields, &fgpa, nullptr)) return false;
    out->gpa = clsGpa;
    out->fields_gpa = fgpa;
    out->name_ptr = name;
    out->fc = fc;
    out->ok = true;
    return true;
}

static bool ValidateClassAt(uint64_t cr3, uint64_t loc, uint64_t namePtr,
                            uint32_t wantFc, const char* f0name, ClassInfo* out)
{
    if (loc < 0x10) return false;
    uint64_t cls = loc - 0x10;
    uint64_t name = 0, fields = 0, f0 = 0, fgpa = 0;
    uint16_t fc = 0;
    GuestRead64(cls + 0x10, &name);
    GuestRead64(cls + 0x80, &fields);
    GuestRead(cls + 0x124, &fc, 2);
    if (name != namePtr || !fields || fc != wantFc) return false;
    // The FieldInfo array is native heap memory and Android may swap it out
    // (probe 31: the PTE's present bit is clear), in which case translating
    // `fields` fails even though the class itself is resident.  Then accept
    // on name pointer + field count alone and keep the verified inline
    // offsets (the caller's fallbacks).
    if (X64Translate(cr3, fields, &fgpa, nullptr)) {
        GuestRead64(fgpa, &f0);
        // The FieldInfo array may be resident while the metadata string page
        // holding the field names is paged out.  An empty read is "unknown",
        // not a mismatch, so only reject on a non-empty wrong name.
        if (f0name && f0) {
            std::string f0s = X64ReadString(cr3, f0, 48);
            if (!f0s.empty() && f0s != f0name) return false;
        }
        out->gpa = cls;
        out->fields_gpa = fgpa;
        out->name_ptr = namePtr;
        out->fc = fc;
        out->ok = true;
        return true;
    }
    out->gpa = cls;
    out->fields_gpa = 0;
    out->name_ptr = namePtr;
    out->fc = fc;
    out->ok = true;
    return true;
}

// Find the metadata base GVA inside one CR3 by mapping the metadata magic
// page.  The class-name strings are NOT read here: Android may page out the
// metadata file pages (probe 32: strings returned "", magic page resident),
// so the base is taken from the page-aligned magic GVA and validated later by
// finding CharacterMotor name pointers at base+OFF_CM_NAME.
static bool FindMetaBaseInCr3(uint64_t cr3, uint64_t magicGpa, uint64_t* outBase)
{
    if (!magicGpa) return false;
    uint64_t page = magicGpa & ~0xFFFULL;
    auto w = WalkCr3ForPages(cr3, { page });
    auto it = w.find(page);
    if (it == w.end()) return false;

    for (uint64_t g : it->second) {
        if (g >= 0x800000000000ULL) continue;   // user space only
        uint64_t m0 = g | (magicGpa & 0xFFF);
        uint64_t cand[2] = { m0, g };
        for (uint64_t m : cand) {
            uint64_t mgpa = 0;
            uint32_t magic = 0;
            if (!X64Translate(cr3, m, &mgpa, nullptr)) continue;
            if (!GuestRead32(mgpa, &magic) || magic != 0xFAB11BAF) continue;
            if (m & 0xFFF) continue;            // magic is at file offset 0
            *outBase = m;
            return true;
        }
    }
    return false;
}

static bool Stage4ClassesOnce()
{
    LOG("=== STAGE 4: metadata + il2cpp classes ===");

    if (g_magicGpas.empty()) {
        g_magicGpas = FindMetaMagicGpas();
        LOG("stage 4: %zu metadata magic copies", g_magicGpas.size());
        for (uint64_t m : g_magicGpas)
            LOG("  magic GPA=%016llX", (unsigned long long)m);
        if (g_magicGpas.empty()) return false;
    }

    if (g_metas.empty()) {
        for (uint64_t mg : g_magicGpas) {
            std::vector<LeafRef> leaves = { { mg & ~0xFFFULL, mg & 0xFFF } };
            auto chains = ChainsForLeaves(leaves, 32768);
            LOG("stage 4: magic %016llX -> %zu mappings", (unsigned long long)mg,
                chains.size());
            for (const auto& c : chains) {
                uint64_t m = c.gva;            // magic sits at metadata base
                uint64_t mgpa = 0;
                uint32_t magic = 0;
                if (!X64Translate(c.cr3, m, &mgpa, nullptr)) continue;
                if (!GuestRead32(mgpa, &magic) || magic != 0xFAB11BAF) continue;
                // Do not require the class-name strings here: the metadata
                // file pages can be paged out (probe 32) even while the magic
                // page is resident.  Keep only the geometric checks; class
                // discovery below re-validates the base by finding
                // CharacterMotor name pointers at base+OFF_CM_NAME.
                if (m & 0xFFF) continue;
                if (m >= 0x800000000000ULL) continue;
                bool dup = false;
                for (const auto& e : g_metas)
                    if (e.cr3 == c.cr3 && e.base == m) { dup = true; break; }
                if (dup) continue;
                LOG("stage 4: metadata base %016llX in CR3 %016llX",
                    (unsigned long long)m, (unsigned long long)c.cr3);
                g_metas.push_back({ c.cr3, m });
            }
        }
        if (g_metas.empty()) { LOG("stage 4: no metadata base found"); return false; }
    }

    // Try each (cr3, base) until the CharacterMotor class exists.
    for (const auto& mc : g_metas) {
        uint64_t namePtr = mc.base + OFF_CM_NAME;
        auto locs = FindQwordsAny({ namePtr }, 4096);
        LOG("stage 4: CR3=%016llX base=%016llX class-name qwords=%zu",
            (unsigned long long)mc.cr3, (unsigned long long)mc.base, locs.size());
        if (locs.empty()) continue;

        ClassInfo cm;
        for (uint64_t loc : locs) {
            if (ValidateClassAt(mc.cr3, loc, namePtr, 40,
                                "MinimalVerticalSpeed", &cm)) break;
        }
        if (!cm.ok) continue;

        // Resolve LaneStateInfo through CharacterMotor.field[27]'s Il2CppType.
        // Scanning for the metadata name pointer finds a *different* class
        // with the same name (probe 28/29: type data.klass MISMATCH) whose
        // field offsets do not match the inline struct.
        ClassInfo lsi;
        {
            int fi = FindFieldIndexByName(mc.cr3, cm, "_laneStateInfo");
            uint64_t typeGva = 0;
            if (fi >= 0)
                GuestRead64(cm.fields_gpa + (uint64_t)fi * 0x20 + 0x08, &typeGva);
            uint64_t typeGpa = 0, klassGva = 0, klassGpa = 0;
            if (typeGva && X64Translate(mc.cr3, typeGva, &typeGpa, nullptr)) {
                GuestRead64(typeGpa, &klassGva);
                if (klassGva && X64Translate(mc.cr3, klassGva, &klassGpa, nullptr)) {
                    ClassInfo ci;
                    if (LoadClassAt(mc.cr3, klassGpa, &ci)) {
                        lsi = ci;
                        LOG("stage 4: LaneStateInfo via field type GPA=%016llX fc=%u",
                            (unsigned long long)lsi.gpa, lsi.fc);
                    } else {
                        LOG("stage 4: field type klass GPA=%016llX not loadable;"
                            " using verified inline offsets",
                            (unsigned long long)klassGpa);
                    }
                }
            }
            if (!lsi.ok)
                LOG("stage 4: LaneStateInfo type unresolved; using verified"
                    " offsets targetLane=+0x%X changing=+0x%X",
                    FB_TARGET_LANE, FB_CHANGING);
        }

        g_cr3 = mc.cr3;
        g_metaBase = mc.base;
        g_cm = cm;
        g_lsi = lsi;
        LOG("stage 4: CharacterMotor class GPA=%016llX fc=%u fields=%016llX",
            (unsigned long long)g_cm.gpa, g_cm.fc,
            (unsigned long long)g_cm.fields_gpa);
        if (g_lsi.ok)
            LOG("stage 4: LaneStateInfo class GPA=%016llX fc=%u",
                (unsigned long long)g_lsi.gpa, g_lsi.fc);

        offLaneState    = FindFieldOffsetByName(g_cr3, g_cm, "_laneStateInfo", FB_LANE_STATE);
        offController   = FindFieldOffsetByName(g_cr3, g_cm, "_controller", FB_CONTROLLER);
        offCurrentState = FindFieldOffsetByName(g_cr3, g_cm, "_currentState", FB_CURRENT_ST);
        offAllowInput   = FindFieldOffsetByName(g_cr3, g_cm, "<AllowInput>k__BackingField", FB_ALLOW_INPUT);
        offVelocity     = FindFieldOffsetByName(g_cr3, g_cm, "Velocity", FB_VELOCITY);
        offIsActive     = FindFieldOffsetByName(g_cr3, g_cm, "<IsActive>k__BackingField", FB_IS_ACTIVE);
        offAccelerate   = FindFieldOffsetByName(g_cr3, g_cm, "_canAccelerate", FB_ACCELERATE);
        if (g_lsi.ok) {
            offTargetLane = FindFieldOffsetByName(g_cr3, g_lsi, "TargetLane", FB_TARGET_LANE);
            offChanging   = FindFieldOffsetByName(g_cr3, g_lsi, "IsChangingLane", FB_CHANGING);
        }
        LOG("stage 4: offsets laneState=+0x%X controller=+0x%X currentState=+0x%X",
            offLaneState, offController, offCurrentState);
        LOG("stage 4: allow=+0x%X active=+0x%X accel=+0x%X velocity=+0x%X"
            " targetLane=+0x%X changing=+0x%X",
            offAllowInput, offIsActive, offAccelerate, offVelocity,
            offTargetLane, offChanging);

        std::set<uint64_t> classPages = { g_cm.gpa & ~0xFFFULL };
        auto cmMapped = WalkCr3ForPages(g_cr3, classPages);
        g_cmClassPtrs.clear();
        auto it = cmMapped.find(g_cm.gpa & ~0xFFFULL);
        if (it != cmMapped.end())
            for (uint64_t g : it->second)
                g_cmClassPtrs.insert(g + (g_cm.gpa & 0xFFF));
        LOG("stage 4: class pointer GVAs=%zu", g_cmClassPtrs.size());
        for (uint64_t g : g_cmClassPtrs)
            LOG("  class ptr %016llX", (unsigned long long)g);
        return !g_cmClassPtrs.empty();
    }
    LOG("stage 4: CharacterMotor class not initialized yet");
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 5 — player CharacterMotor
// ─────────────────────────────────────────────────────────────────────────────
struct Motor {
    uint64_t gpa = 0;
    int32_t target = 0;
    uint8_t chg = 0, allow = 0, active = 0, accel = 0;
    float vx = 0, vy = 0, vz = 0;
    uint64_t ctrl = 0, state = 0;
    std::string ctrlClass;
};

static void ReadMotor(uint64_t ip, Motor* m)
{
    m->gpa = ip;
    GuestRead32(ip + offLaneState + offTargetLane, (uint32_t*)&m->target);
    GuestRead(ip + offLaneState + offChanging, &m->chg, 1);
    GuestRead(ip + offAllowInput, &m->allow, 1);
    GuestRead(ip + offIsActive, &m->active, 1);
    GuestRead(ip + offAccelerate, &m->accel, 1);
    GuestRead32(ip + offVelocity, (uint32_t*)&m->vx);
    GuestRead32(ip + offVelocity + 4, (uint32_t*)&m->vy);
    GuestRead32(ip + offVelocity + 8, (uint32_t*)&m->vz);
    GuestRead64(ip + offController, &m->ctrl);
    GuestRead64(ip + offCurrentState, &m->state);
}

static bool MotorSane(const Motor& m)
{
    if (m.target < -2 || m.target > 2) return false;
    if (m.chg > 1 || m.allow > 1 || m.active > 1 || m.accel > 1) return false;
    if (!std::isfinite(m.vx) || !std::isfinite(m.vy) || !std::isfinite(m.vz)) return false;
    if (fabsf(m.vx) > 200 || fabsf(m.vy) > 200 || fabsf(m.vz) > 200) return false;
    return true;
}

static bool MotorStillValid(uint64_t gpa)
{
    if (!gpa) return false;
    uint64_t klass = 0;
    if (!GuestRead64(gpa, &klass)) return false;
    return g_cmClassPtrs.count(klass) != 0;
}

static bool FindPlayerMotor()
{
    LOG("=== STAGE 5: player CharacterMotor ===");
    if (!g_cm.ok || g_cmClassPtrs.empty()) return false;

    for (int round = 0; round < 4; round++) {
        if (round) { LOG("stage 5: retry %d in 3s", round); Sleep(3000); }

        auto hits = FindQwordsAny(g_cmClassPtrs, 8192);
        std::vector<Motor> sane;
        size_t monitorZero = 0, laneOk = 0, flagsOk = 0;
        for (uint64_t ip : hits) {
            uint64_t monitor = 1;
            GuestRead64(ip + 8, &monitor);
            if (monitor != 0) continue;
            monitorZero++;
            Motor m;
            ReadMotor(ip, &m);
            if (m.target < -2 || m.target > 2) continue;
            laneOk++;
            if (m.chg > 1 || m.allow > 1 || m.active > 1 || m.accel > 1) continue;
            flagsOk++;
            if (!MotorSane(m)) continue;
            sane.push_back(m);
        }
        LOG("stage 5: round %d hits=%zu monitor0=%zu laneOk=%zu flagsOk=%zu sane=%zu",
            round + 1, hits.size(), monitorZero, laneOk, flagsOk, sane.size());

        const Motor* pick = nullptr;
        for (const auto& m : sane)
            if (m.allow && m.active && fabsf(m.vz) >= 0.5f)
                if (!pick || fabsf(m.vz) > fabsf(pick->vz)) pick = &m;
        if (!pick)
            for (const auto& m : sane)
                if (m.allow && m.active) { pick = &m; break; }
        if (!pick && sane.size() == 1) pick = &sane[0];

        if (!pick) {
            for (auto& m : sane) {
                m.ctrlClass = ClassNameAt(g_cr3, m.ctrl);
                LOG("stage 5: candidate %016llX target=%d chg=%u allow=%u active=%u"
                    " accel=%u vel=(%.2f,%.2f,%.2f) ctrl=%s",
                    (unsigned long long)m.gpa, m.target, m.chg, m.allow, m.active,
                    m.accel, m.vx, m.vy, m.vz, m.ctrlClass.c_str());
            }
            continue;
        }

        uint64_t laneGpa = pick->gpa + offLaneState + offTargetLane;
        g_motorGpa.store(pick->gpa);
        g_autoLaneGpa.store(laneGpa);
        std::string cc = ClassNameAt(g_cr3, pick->ctrl);
        LOG("stage 5: PLAYER motor=%016llX target=%d allow=%u active=%u accel=%u"
            " vel=(%.2f,%.2f,%.2f) ctrl=%s",
            (unsigned long long)pick->gpa, pick->target, pick->allow, pick->active,
            pick->accel, pick->vx, pick->vy, pick->vz, cc.c_str());
        LOG("stage 5: LANE_GPA=%016llX", (unsigned long long)laneGpa);
        return true;
    }
    LOG("stage 5: no active player motor found (paused / loading?)");
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane read + cache validation
// ─────────────────────────────────────────────────────────────────────────────
static bool LaneRead(int32_t* out)
{
    if (!out) return false;
    uint64_t gpa = g_useUserGpa.load() ? g_userGpa.load() : g_autoLaneGpa.load();
    if (!gpa) return false;
    int32_t v = 0;
    if (!GuestRead(gpa, &v, 4)) return false;
    if (v < -1 || v > 1) return false;
    *out = v;
    return true;
}

static void ValidateCachedMotor()
{
    if (g_useUserGpa.load()) return;
    uint64_t motor = g_motorGpa.load();
    if (!motor) return;
    if (!MotorStillValid(motor)) {
        LOG("lane: cached motor %016llX invalid, re-discovering",
            (unsigned long long)motor);
        g_motorGpa.store(0);
        g_autoLaneGpa.store(0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe
// ─────────────────────────────────────────────────────────────────────────────
static bool PipeSend(HANDLE pipe, const char* msg)
{
    DWORD written = 0;
    return WriteFile(pipe, msg, (DWORD)strlen(msg), &written, nullptr) == TRUE;
}

static bool PipeReadLine(HANDLE pipe, char* buf, DWORD bufsz)
{
    DWORD i = 0;
    while (i < bufsz - 1) {
        char c = 0;
        DWORD got = 0;
        if (!ReadFile(pipe, &c, 1, &got, nullptr) || got == 0) return false;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = 0;
    return true;
}

static void EmitLane(HANDLE pipe, int32_t val, int32_t* prev)
{
    if (val == *prev) return;
    char resp[32];
    snprintf(resp, sizeof(resp), "LANE %d\n", val);
    if (PipeSend(pipe, resp)) *prev = val;
}

static void HandleRead(HANDLE pipe)
{
    int32_t val = 0;
    char resp[32];
    if (g_useUserGpa.load() && g_userGpa.load() == 0)
        snprintf(resp, sizeof(resp), "ERR no GPA set\n");
    else if (LaneRead(&val))
        snprintf(resp, sizeof(resp), "LANE %d\n", val);
    else
        snprintf(resp, sizeof(resp), "LANE ?\n");
    PipeSend(pipe, resp);
}

static void HandleSetGpa(HANDLE pipe, const char* hex)
{
    uint64_t gpa = 0;
    if (sscanf(hex, "%llx", &gpa) == 1 && gpa < g_x64Ceiling) {
        g_userGpa.store(gpa);
        g_useUserGpa.store(true);
        LOG("pipe: SET_GPA %016llX (manual override)", (unsigned long long)gpa);
        PipeSend(pipe, "OK\n");
    } else {
        PipeSend(pipe, "ERR bad GPA\n");
    }
}

static DWORD WINAPI PipeClientThread(LPVOID arg)
{
    HANDLE pipe = (HANDLE)arg;
    char buf[256];

    if (!g_bridgeReady.load()) {
        PipeSend(pipe, "STATUS BRIDGE_NOT_READY\n");
    } else {
        char banner[128];
        snprintf(banner, sizeof(banner),
                 "STATUS READY HVA_BASE %016llX\n", (unsigned long long)g_hvaBase);
        PipeSend(pipe, banner);
    }

    while (true) {
        if (!PipeReadLine(pipe, buf, sizeof(buf))) break;

        if (strcmp(buf, "PING") == 0) {
            if (!PipeSend(pipe, "PONG\n")) break;
        }
        else if (strcmp(buf, "HVA_BASE") == 0) {
            char resp[64];
            snprintf(resp, sizeof(resp), "HVA_BASE %016llX\n",
                     (unsigned long long)g_hvaBase);
            if (!PipeSend(pipe, resp)) break;
        }
        else if (strncmp(buf, "SET_GPA ", 8) == 0) {
            uint64_t gpa = 0;
            if (sscanf(buf + 8, "%llx", &gpa) == 1 && gpa < g_x64Ceiling) {
                g_userGpa.store(gpa);
                g_useUserGpa.store(true);
                LOG("pipe: SET_GPA %016llX (manual override)", (unsigned long long)gpa);
                if (!PipeSend(pipe, "OK\n")) break;
            } else {
                if (!PipeSend(pipe, "ERR bad GPA\n")) break;
            }
        }
        else if (strcmp(buf, "READ") == 0) {
            HandleRead(pipe);
        }
        else if (strcmp(buf, "START") == 0) {
            g_streaming.store(true);
            if (!PipeSend(pipe, "OK\n")) break;

            int32_t prev = 999;
            bool bad = false;
            while (g_streaming.load()) {
                int32_t val = 0;
                if (LaneRead(&val)) {
                    EmitLane(pipe, val, &prev);
                    bad = false;
                } else if (!bad) {
                    if (!PipeSend(pipe, "LANE ?\n")) goto client_done;
                    prev = -99;
                    bad = true;
                }

                DWORD avail = 0;
                if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                    char cmd[256] = {};
                    if (!PipeReadLine(pipe, cmd, sizeof(cmd))) goto client_done;

                    if (strcmp(cmd, "STOP") == 0) {
                        g_streaming.store(false);
                        PipeSend(pipe, "OK\n");
                        break;
                    }
                    else if (strncmp(cmd, "SET_GPA ", 8) == 0) {
                        HandleSetGpa(pipe, cmd + 8);
                        prev = 999;
                        bad = false;
                    }
                    else if (strcmp(cmd, "PING") == 0) {
                        if (!PipeSend(pipe, "PONG\n")) goto client_done;
                    }
                    else if (strcmp(cmd, "READ") == 0) {
                        HandleRead(pipe);
                    }
                }
                Sleep(16);
            }
        }
        else if (strcmp(buf, "STOP") == 0) {
            g_streaming.store(false);
            if (!PipeSend(pipe, "OK\n")) break;
        }
        else {
            char resp[160];
            snprintf(resp, sizeof(resp), "ERR unknown command: %s\n", buf);
            if (!PipeSend(pipe, resp)) break;
        }
    }

client_done:
    LOG("pipe client disconnected");
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

static DWORD WINAPI PipeServerThread(LPVOID)
{
    LOG("pipe server started: " PIPE_NAME);
    while (true) {
        HANDLE pipe = CreateNamedPipeA(
            PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            LOG("CreateNamedPipe failed: %lu", GetLastError());
            Sleep(1000);
            continue;
        }
        if (!ConnectNamedPipe(pipe, nullptr)) {
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_CONNECTED) { CloseHandle(pipe); continue; }
        }
        LOG("pipe client connected");
        CreateThread(nullptr, 0, PipeClientThread, (LPVOID)pipe, 0, nullptr);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker loop
// ─────────────────────────────────────────────────────────────────────────────
static void ResetDiscovery()
{
    g_cr3s.clear();
    g_metas.clear();
    g_metaBase = 0;
    g_metaCr3 = 0;
    g_magicGpas.clear();
    g_cr3 = 0;
    g_cm = {};
    g_lsi = {};
    g_cmClassPtrs.clear();
    g_motorGpa.store(0);
    g_autoLaneGpa.store(0);
}

static DWORD WINAPI WorkerThread(LPVOID)
{
    if (!Stage1Bridge() || !Stage2Ranges()) {
        LOG("worker: bridge/range map failed; pipe stays BRIDGE_NOT_READY");
        return 0;
    }
    g_bridgeReady.store(true);
    LOG("bridge ready — pipe accepts clients");

    int emptyRounds = 0;
    bool stage3Tried = false;
    while (true) {
        if (!g_useUserGpa.load()) {
            if (!stage3Tried) {
                stage3Tried = true;
                if (!Stage3Cr3s())
                    LOG("worker: stage 3 found no CR3; stage 4 will still try");
            }
            if (!g_cm.ok) {
                if (!Stage4ClassesOnce()) { Sleep(5000); continue; }
            }
            if (g_motorGpa.load() == 0 || !MotorStillValid(g_motorGpa.load())) {
                if (!FindPlayerMotor()) {
                    if (g_motorGpa.load() == 0) emptyRounds++;
                    if (emptyRounds >= 3) {
                        LOG("worker: repeated empty scans, resetting discovery");
                        ResetDiscovery();
                        emptyRounds = 0;
                    }
                } else {
                    emptyRounds = 0;
                }
            } else {
                ValidateCachedMotor();
            }
        }
        Sleep(1000);
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// DllMain
// ─────────────────────────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_log = fopen(LOG_PATH, "w");
        if (!g_log) return FALSE;
        LOG("recon_android11 — BlueStacks 5 / Android 11 lane reader");
        LOG("PID=%lu", GetCurrentProcessId());

        CreateThread(nullptr, 0, PipeServerThread, nullptr, 0, nullptr);
        CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
