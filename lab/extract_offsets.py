#!/usr/bin/env python3
"""
extract_offsets.py v4
- fixes pair table indexing (v31 layout probe)
- fixes field_start offset in Il2CppTypeDefinition struct
- coverage check for field_to_typedef map
- brute-force lane field scan with owner resolution
- parent chain walk with corrected typeIndex resolution
- vtable RVA scan

Usage:  py -3 extract_offsets.py base.apk
Output: offsets.json
"""

import sys, zipfile, struct, json

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "offsets.json"

TARGET_FIELD  = "_currentLaneIndex"
LANE_KEYWORDS = ["lane", "Lane"]

# ── extract ───────────────────────────────────────────────────────────────────

print(f"[*] opening {APK}")
with zipfile.ZipFile(APK, 'r') as z:
    names     = z.namelist()
    lib_data  = z.read(next(n for n in names if n.endswith("arm64-v8a/libil2cpp.so")))
    meta_data = z.read(next(n for n in names if n.endswith("global-metadata.dat")))

print(f"[*] libil2cpp.so  : {len(lib_data):,} bytes")
print(f"[*] global-metadata: {len(meta_data):,} bytes")

magic, version = struct.unpack_from("<II", meta_data, 0)
assert magic == 0xFAB11BAF
print(f"[*] metadata version: {version}")

# ── pair table ────────────────────────────────────────────────────────────────
# pair[N] = (offset, size) at byte 8 + N*8
# v27/v29 layout (used as baseline, probed below):
#   2  = strings
#   10 = fieldDefs
#   11 = fieldOffsets
#   19 = typeDefs
#   20 = typeIndices (Il2CppTypeIndex[])
#
# v31 may have shifted entries — we probe pair[20] size vs n_types
# and try alternate indices if it looks wrong.

def pair(idx):
    return struct.unpack_from("<II", meta_data, 8 + idx * 8)

str_off,  _        = pair(2)
type_off, type_sz  = pair(19)   # Il2CppTypeDefinition[]
fdef_off, fdef_sz  = pair(10)   # Il2CppFieldDefinition[]
foff_off, foff_sz  = pair(11)   # uint32 field offsets[]

TD_SIZE = 88
FD_SIZE = 12

n_types  = type_sz  // TD_SIZE
n_fields = fdef_sz  // FD_SIZE

print(f"[*] n_types={n_types}  n_fields={n_fields}")

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel : end].decode('utf-8', errors='replace')

# ── probe typeIndex table ─────────────────────────────────────────────────────
# pair[20] in v27 is Il2CppTypeIndex[] — but in v31 this may have moved.
# A valid typeIndex table must have entries that are valid typedef indices
# (< n_types). We try pairs 20..30 and pick the first one that looks right.

def probe_tidx_pair(idx):
    off, sz = pair(idx)
    n = sz // 4
    if n < 100:
        return False, 0, 0, 0
    # sample 20 entries — all should be < n_types
    sample = min(20, n)
    for i in range(sample):
        val, = struct.unpack_from("<I", meta_data, off + i * 4)
        if val >= n_types:
            return False, 0, 0, 0
    return True, off, sz, n

tidx_off = tidx_sz = n_tidx = 0
for probe_i in range(20, 32):
    ok, off, sz, n = probe_tidx_pair(probe_i)
    if ok:
        tidx_off, tidx_sz, n_tidx = off, sz, n
        print(f"[*] typeIndex table: pair[{probe_i}]  entries={n_tidx}")
        break

if not n_tidx:
    print("[!] could not locate typeIndex table — parent chain will be limited")

def tidx_to_typedef(tidx):
    if not n_tidx or tidx < 0 or tidx >= n_tidx:
        return None
    val, = struct.unpack_from("<I", meta_data, tidx_off + tidx * 4)
    if val >= n_types:
        return None
    return val

# ── probe field_start offset in Il2CppTypeDefinition ─────────────────────────
# In v27 the struct layout (88 bytes) has field_start at byte 36.
# In v31 it may have shifted. We probe by checking which dword offset
# produces field_start values that, when summed with field_count (at a
# nearby offset), stay within n_fields for all types.
#
# Known stable anchors in Il2CppTypeDefinition (all versions):
#   +0  nameIndex   (uint32, into string table)
#   +4  namespaceIndex (uint32)
# We use those to find cstr() for type 0 as a sanity check.
#
# field_count is a uint16 — in v27 it sits at TD+72.
# We try field_start at offsets 32, 36, 40, 44 and field_count at 68..76.

def probe_field_layout():
    # Try a grid of (fs_off, fc_off) combinations
    for fs_off in (32, 36, 40, 44):
        for fc_off in (68, 70, 72, 74, 76):
            ok = True
            total = 0
            for i in range(min(500, n_types)):
                b = type_off + i * TD_SIZE
                fs, = struct.unpack_from("<I", meta_data, b + fs_off)
                fc, = struct.unpack_from("<H", meta_data, b + fc_off)
                if fc > 0:
                    if fs + fc > n_fields:
                        ok = False
                        break
                    total += fc
            if ok and total > 1000:   # sanity: at least 1000 fields assigned
                return fs_off, fc_off
    return 36, 72  # fall back to v27 defaults

fs_off, fc_off = probe_field_layout()
print(f"[*] Il2CppTypeDefinition: field_start@+{fs_off}  field_count@+{fc_off}")

# parent_tidx: in v27 it's a signed int32 at TD+20
# We keep this assumption but fall back gracefully if resolution fails
PARENT_OFF = 20

# ── build typedef table ───────────────────────────────────────────────────────

print(f"[*] building typedef table...")
all_types = []
for i in range(n_types):
    b = type_off + i * TD_SIZE
    try:
        name_idx, ns_idx    = struct.unpack_from("<II", meta_data, b)
        field_start,        = struct.unpack_from("<I",  meta_data, b + fs_off)
        parent_type_idx,    = struct.unpack_from("<i",  meta_data, b + PARENT_OFF)
        field_count,        = struct.unpack_from("<H",  meta_data, b + fc_off)
        all_types.append({
            'name':        cstr(name_idx),
            'ns':          cstr(ns_idx),
            'field_start': field_start,
            'field_count': field_count,
            'parent_tidx': parent_type_idx,
            'typedef_idx': i,
        })
    except Exception:
        all_types.append(None)

# ── field → typedef map ───────────────────────────────────────────────────────

field_to_typedef = {}
for td in all_types:
    if td is None or td['field_count'] == 0:
        continue
    for fi in range(td['field_count']):
        abs_fi = td['field_start'] + fi
        if 0 <= abs_fi < n_fields and abs_fi not in field_to_typedef:
            field_to_typedef[abs_fi] = td['typedef_idx']

known = len(field_to_typedef)
print(f"[*] field_to_typedef coverage: {known}/{n_fields} ({100*known/n_fields:.1f}%)")
if known / n_fields < 0.5:
    print("[!] coverage < 50% — field_start probe may still be wrong; results may have unknown owners")

# ── scan ALL fields for lane-related names ────────────────────────────────────

print(f"\n[*] scanning all {n_fields} fields for lane-related names...")

lane_fields  = []
target_hits  = []

for abs_fi in range(n_fields):
    b = fdef_off + abs_fi * FD_SIZE
    try:
        name_idx, = struct.unpack_from("<I", meta_data, b)
        fname = cstr(name_idx)
    except Exception:
        continue

    is_lane   = any(k in fname for k in LANE_KEYWORDS)
    is_target = fname == TARGET_FIELD
    if not is_lane and not is_target:
        continue

    raw, = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
    foff   = raw & 0x7FFFFFFF
    static = bool(raw & 0x80000000)

    owner_td_idx = field_to_typedef.get(abs_fi)
    if owner_td_idx is not None and all_types[owner_td_idx]:
        owner = all_types[owner_td_idx]
        owner_name = f"{owner['ns']}.{owner['name']}" if owner['ns'] else owner['name']
    else:
        owner_name = "<unknown typedef>"

    entry = {
        'field_name': fname,
        'abs_fi':     abs_fi,
        'offset':     foff,
        'static':     static,
        'owner':      owner_name,
    }
    lane_fields.append(entry)
    if is_target:
        target_hits.append(entry)

print(f"[*] found {len(lane_fields)} lane-related field(s):")
for e in lane_fields:
    marker = " ← EXACT MATCH" if e['field_name'] == TARGET_FIELD else ""
    sane = " [SANE]" if 0x10 <= e['offset'] <= 0x1000 and not e['static'] else ""
    print(f"    {e['owner']}.{e['field_name']}  offset={e['offset']:#x}  static={e['static']}{sane}{marker}")

# ── parent chain walk ─────────────────────────────────────────────────────────

print(f"\n[*] walking parent chain of CharacterInputController:")

cic = next((td for td in all_types
            if td and td['name'] == 'CharacterInputController'
            and td['ns'] == 'SYBO.RunnerCore.Character'), None)

if not cic:
    print("[!] CharacterInputController not found")
else:
    visited = set()
    cur     = cic
    depth   = 0
    while cur:
        cur_key = cur['typedef_idx']
        if cur_key in visited:
            print(f"  [depth {depth}] circular, stopping")
            break
        visited.add(cur_key)
        ns_name = f"{cur['ns']}.{cur['name']}" if cur['ns'] else cur['name']
        print(f"  [depth {depth}] {ns_name}  fields={cur['field_count']}  parent_tidx={cur['parent_tidx']}")

        for fi in range(cur['field_count']):
            abs_fi = cur['field_start'] + fi
            b = fdef_off + abs_fi * FD_SIZE
            try:
                name_idx, = struct.unpack_from("<I", meta_data, b)
                fname     = cstr(name_idx)
                raw,      = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
                foff      = raw & 0x7FFFFFFF
                static    = bool(raw & 0x80000000)
                marker    = " ← TARGET" if fname == TARGET_FIELD else ""
                print(f"    field: '{fname}'  offset={foff:#x}  static={static}{marker}")
            except Exception as ex:
                print(f"    field {abs_fi}: error {ex}")

        pidx = cur['parent_tidx']
        if pidx < 0 or pidx == 0x7FFFFFFF:
            print(f"  [depth {depth}] no parent (pidx={pidx}), stopping")
            break

        td_idx = tidx_to_typedef(pidx)
        if td_idx is None:
            # try treating pidx as a direct typedef index as fallback
            if 0 <= pidx < n_types and all_types[pidx]:
                print(f"  [depth {depth}] typeIndex {pidx} out of tidx table — trying as direct typedef")
                td_idx = pidx
            else:
                print(f"  [depth {depth}] parent pidx={pidx} unresolvable, stopping")
                break

        next_td = all_types[td_idx] if td_idx < len(all_types) else None
        if next_td is None:
            print(f"  [depth {depth}] parent typedef {td_idx} unreadable, stopping")
            break

        cur   = next_td
        depth += 1
        if depth > 20:
            print("  [depth limit reached]")
            break

# ── pick best result ──────────────────────────────────────────────────────────

best = None
if target_hits:
    candidates = [e for e in target_hits if not e['static'] and 0x10 <= e['offset'] <= 0x1000]
    best = candidates[0] if candidates else target_hits[0]
    print(f"\n[*] using exact match: {best['owner']}.{best['field_name']}  offset={best['offset']:#x}")
elif lane_fields:
    candidates = [e for e in lane_fields
                  if not e['static'] and 0x10 <= e['offset'] <= 0x1000
                  and e['owner'] != '<unknown typedef>']
    if not candidates:
        # relax owner requirement
        candidates = [e for e in lane_fields if not e['static'] and 0x10 <= e['offset'] <= 0x1000]
    if candidates:
        # prefer currentLane or laneIndex over generic laneDirection
        priority = [e for e in candidates if e['field_name'] in ('currentLane', 'laneIndex', '_currentLaneIndex')]
        best = priority[0] if priority else candidates[0]
        print(f"\n[*] no exact match — using best lane field: {best['owner']}.{best['field_name']}  offset={best['offset']:#x}")

if not best:
    print("\n[!] no usable lane field found")

# ── ELF vtable scan ───────────────────────────────────────────────────────────

vtable_rva     = None
il2cpp_class_rva = None

if best and best['owner'] != '<unknown typedef>':
    class_simple = best['owner'].split('.')[-1]
    class_ns     = '.'.join(best['owner'].split('.')[:-1])

    assert lib_data[:4] == b'\x7fELF'
    e_phoff, = struct.unpack_from("<Q", lib_data, 32)
    e_phnum, = struct.unpack_from("<H", lib_data, 56)
    load_segs = []
    for i in range(e_phnum):
        ph = e_phoff + i * 56
        if struct.unpack_from("<I", lib_data, ph)[0] != 1:
            continue
        p_offset, = struct.unpack_from("<Q", lib_data, ph + 8)
        p_vaddr,  = struct.unpack_from("<Q", lib_data, ph + 16)
        p_filesz, = struct.unpack_from("<Q", lib_data, ph + 32)
        load_segs.append((p_vaddr, p_offset, p_filesz))

    def foff_to_rva(fo):
        for v, o, s in load_segs:
            if o <= fo < o + s:
                return v + (fo - o)
        return None

    def rva_to_foff(rva):
        for v, o, s in load_segs:
            if v <= rva < v + s:
                return o + (rva - v)
        return None

    needle = class_simple.encode() + b'\x00'
    hits   = []
    pos    = 0
    while True:
        p = lib_data.find(needle, pos)
        if p == -1:
            break
        rva = foff_to_rva(p)
        if rva:
            hits.append((p, rva))
        pos = p + 1

    print(f"[*] '{class_simple}' string: {len(hits)} hit(s) in libil2cpp.so")

    for (sfoff, srva) in hits:
        needle2 = struct.pack("<Q", srva)
        pos2 = 0
        while True:
            p2 = lib_data.find(needle2, pos2)
            if p2 == -1:
                break
            pos2 += 8
            class_rva = foff_to_rva(p2)
            if class_rva is None:
                continue
            class_base = class_rva - 0x10
            cfoff      = rva_to_foff(class_base)
            if cfoff is None or cfoff + 0x20 > len(lib_data):
                continue
            ns_ptr_rva, = struct.unpack_from("<Q", lib_data, cfoff + 0x18)
            ns_foff     = rva_to_foff(ns_ptr_rva)
            if ns_foff is None:
                continue
            try:
                ns_end = lib_data.index(b'\x00', ns_foff)
                ns_str = lib_data[ns_foff:ns_end].decode('utf-8', errors='replace')
            except Exception:
                continue
            if ns_str != class_ns:
                continue
            il2cpp_class_rva = class_base
            vtable_rva       = class_base + 0x128
            print(f"[*] Il2CppClass* RVA = {il2cpp_class_rva:#x}  vtable RVA = {vtable_rva:#x}")
            break
        if vtable_rva:
            break

    if not vtable_rva:
        print("[!] vtable not found via ELF scan — will need runtime resolution")
else:
    print("[*] skipping ELF vtable scan (no known owner class)")

# ── output ────────────────────────────────────────────────────────────────────

result = {
    "target_class":        "CharacterInputController",
    "target_namespace":    "SYBO.RunnerCore.Character",
    "target_field":        TARGET_FIELD,
    "found_in_class":      best['owner']   if best else None,
    "field_name_used":     best['field_name'] if best else None,
    "field_offset":        best['offset']  if best else None,
    "il2cpp_class_rva":    il2cpp_class_rva,
    "vtable_rva":          vtable_rva,
    "metadata_version":    version,
    "libil2cpp_size":      len(lib_data),
    "field_layout_probe":  {"field_start_off": fs_off, "field_count_off": fc_off},
    "tidx_coverage":       known,
    "all_lane_fields":     lane_fields,
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] results:")
for k, v in result.items():
    if k in ("all_lane_fields",):
        continue
    print(f"    {k}: {hex(v) if isinstance(v, int) and v is not None else v}")
print(f"[*] written to {OUT}")