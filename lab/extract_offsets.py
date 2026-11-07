#!/usr/bin/env python3
"""
extract_offsets.py v3
- fixes parent resolution (typeIndex → typedef via type table)
- scans ALL 117k fields for _currentLaneIndex regardless of class
- dumps every 'lane' field across the entire metadata
- also tries CharacterMotor since the lane field may live there

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

def pair(idx):
    return struct.unpack_from("<II", meta_data, 8 + idx * 8)

str_off,  _        = pair(2)
type_off, type_sz  = pair(19)   # Il2CppTypeDefinition[]
fdef_off, fdef_sz  = pair(10)   # Il2CppFieldDefinition[]
foff_off, foff_sz  = pair(11)   # uint32 field offsets[]
tidx_off, tidx_sz  = pair(20)   # Il2CppTypeIndex[] (uint32, typeIndex→typedef)

TD_SIZE = 88
FD_SIZE = 12

n_types  = type_sz  // TD_SIZE
n_fields = fdef_sz  // FD_SIZE
n_tidx   = tidx_sz  // 4

print(f"[*] types={n_types}  fields={n_fields}  typeIndexTable={n_tidx}")

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel : end].decode('utf-8', errors='replace')

# ── build typedef table ───────────────────────────────────────────────────────

print(f"[*] building typedef table...")
all_types = []
for i in range(n_types):
    b = type_off + i * TD_SIZE
    try:
        name_idx, ns_idx = struct.unpack_from("<II", meta_data, b)
        field_start      = struct.unpack_from("<I",  meta_data, b + 36)[0]
        parent_type_idx  = struct.unpack_from("<i",  meta_data, b + 20)[0]  # typeIndex (signed)
        field_count      = struct.unpack_from("<H",  meta_data, b + 72)[0]
        all_types.append({
            'name':           cstr(name_idx),
            'ns':             cstr(ns_idx),
            'field_start':    field_start,
            'field_count':    field_count,
            'parent_tidx':    parent_type_idx,  # this is a typeIndex, not typedef index
            'typedef_idx':    i,
        })
    except Exception:
        all_types.append(None)

# typeIndex → typedef index via pair[20]
# pair[20] is the type table: each entry is a uint32 typedef index
def tidx_to_typedef(tidx):
    if tidx < 0 or tidx >= n_tidx:
        return None
    val, = struct.unpack_from("<I", meta_data, tidx_off + tidx * 4)
    if val >= n_types:
        return None
    return val

# ── scan ALL fields for anything with 'lane' in the name ─────────────────────

print(f"\n[*] scanning all {n_fields} fields for lane-related names...")

# build field-name → list of (abs_field_idx, typedef_idx) mapping
# by cross-referencing field ranges in typedef table
field_to_typedef = {}
for td in all_types:
    if td is None or td['field_count'] == 0:
        continue
    for fi in range(td['field_count']):
        abs_fi = td['field_start'] + fi
        if abs_fi not in field_to_typedef:
            field_to_typedef[abs_fi] = td['typedef_idx']

lane_fields   = []  # all fields with 'lane' in name
target_hits   = []  # exact _currentLaneIndex matches

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

    # get offset
    raw, = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
    foff   = raw & 0x7FFFFFFF
    static = bool(raw & 0x80000000)

    # find owning class
    owner_td_idx = field_to_typedef.get(abs_fi)
    if owner_td_idx is not None and all_types[owner_td_idx]:
        owner = all_types[owner_td_idx]
        owner_name = f"{owner['ns']}.{owner['name']}" if owner['ns'] else owner['name']
    else:
        owner_name = f"<unknown typedef>"

    entry = {
        'field_name':   fname,
        'abs_fi':       abs_fi,
        'offset':       foff,
        'static':       static,
        'owner':        owner_name,
    }
    lane_fields.append(entry)
    if is_target:
        target_hits.append(entry)

print(f"[*] found {len(lane_fields)} lane-related field(s):")
for e in lane_fields:
    marker = " ← EXACT MATCH" if e['field_name'] == TARGET_FIELD else ""
    print(f"    {e['owner']}.{e['field_name']}  offset={e['offset']:#x}  static={e['static']}{marker}")

# ── walk parent chain properly using typeIndex table ─────────────────────────

print(f"\n[*] walking parent chain of CharacterInputController (corrected typeIndex):")

# find CharacterInputController typedef
cic = next((td for td in all_types
            if td and td['name'] == 'CharacterInputController'
            and td['ns'] == 'SYBO.RunnerCore.Character'), None)
assert cic, "CharacterInputController not found"

visited = set()
cur = cic
depth = 0
while cur:
    cur_key = cur['typedef_idx']
    if cur_key in visited:
        print(f"  [depth {depth}] circular, stopping")
        break
    visited.add(cur_key)
    ns_name = f"{cur['ns']}.{cur['name']}" if cur['ns'] else cur['name']
    print(f"  [depth {depth}] {ns_name}  fields={cur['field_count']}  parent_tidx={cur['parent_tidx']}")

    if cur['field_count'] > 0:
        for fi in range(cur['field_count']):
            abs_fi = cur['field_start'] + fi
            b = fdef_off + abs_fi * FD_SIZE
            try:
                name_idx, = struct.unpack_from("<I", meta_data, b)
                fname = cstr(name_idx)
                raw,  = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
                foff  = raw & 0x7FFFFFFF
                static = bool(raw & 0x80000000)
                marker = " ← TARGET" if fname == TARGET_FIELD else ""
                print(f"    field: '{fname}'  offset={foff:#x}  static={static}{marker}")
            except Exception as ex:
                print(f"    field {abs_fi}: error {ex}")

    pidx = cur['parent_tidx']
    if pidx < 0 or pidx == 0x7FFFFFFF:
        print(f"  [depth {depth}] no parent (pidx={pidx}), stopping")
        break

    # pidx is a typeIndex — resolve to typedef
    td_idx = tidx_to_typedef(pidx)
    if td_idx is None:
        print(f"  [depth {depth}] parent typeIndex {pidx} → out of range, stopping")
        break

    next_td = all_types[td_idx] if td_idx < len(all_types) else None
    if next_td is None:
        print(f"  [depth {depth}] parent typedef {td_idx} unreadable, stopping")
        break

    cur = next_td
    depth += 1
    if depth > 20:
        print("  [depth limit reached]")
        break

# ── pick best result ──────────────────────────────────────────────────────────

best = None
if target_hits:
    # prefer non-static, lowest sane offset
    candidates = [e for e in target_hits if not e['static'] and 0x10 <= e['offset'] <= 0x1000]
    best = candidates[0] if candidates else target_hits[0]
    print(f"\n[*] using exact match: {best['owner']}.{best['field_name']}  offset={best['offset']:#x}")
elif lane_fields:
    # fall back to first non-static lane field
    candidates = [e for e in lane_fields if not e['static'] and 0x10 <= e['offset'] <= 0x1000]
    if candidates:
        best = candidates[0]
        print(f"\n[*] no exact match — using best lane field: {best['owner']}.{best['field_name']}  offset={best['offset']:#x}")

# ── ELF vtable scan ───────────────────────────────────────────────────────────

vtable_rva = None
il2cpp_class_rva = None

if best:
    class_simple = best['owner'].split('.')[-1]
    class_ns     = '.'.join(best['owner'].split('.')[:-1])

    assert lib_data[:4] == b'\x7fELF'
    e_phoff, = struct.unpack_from("<Q", lib_data, 32)
    e_phnum, = struct.unpack_from("<H", lib_data, 56)
    load_segs = []
    for i in range(e_phnum):
        ph = e_phoff + i * 56
        if struct.unpack_from("<I", lib_data, ph)[0] != 1: continue
        p_offset, = struct.unpack_from("<Q", lib_data, ph + 8)
        p_vaddr,  = struct.unpack_from("<Q", lib_data, ph + 16)
        p_filesz, = struct.unpack_from("<Q", lib_data, ph + 32)
        load_segs.append((p_vaddr, p_offset, p_filesz))

    def foff_to_rva(fo):
        for v, o, s in load_segs:
            if o <= fo < o + s: return v + (fo - o)
        return None

    def rva_to_foff(rva):
        for v, o, s in load_segs:
            if v <= rva < v + s: return o + (rva - v)
        return None

    needle = class_simple.encode() + b'\x00'
    hits = []
    pos = 0
    while True:
        p = lib_data.find(needle, pos)
        if p == -1: break
        rva = foff_to_rva(p)
        if rva: hits.append((p, rva))
        pos = p + 1

    print(f"[*] '{class_simple}' string: {len(hits)} hit(s) in libil2cpp.so")

    for (sfoff, srva) in hits:
        needle2 = struct.pack("<Q", srva)
        pos2 = 0
        while True:
            p2 = lib_data.find(needle2, pos2)
            if p2 == -1: break
            pos2 += 8
            class_rva = foff_to_rva(p2)
            if class_rva is None: continue
            class_base = class_rva - 0x10
            cfoff = rva_to_foff(class_base)
            if cfoff is None or cfoff + 0x20 > len(lib_data): continue
            ns_ptr_rva, = struct.unpack_from("<Q", lib_data, cfoff + 0x18)
            ns_foff = rva_to_foff(ns_ptr_rva)
            if ns_foff is None: continue
            try:
                ns_end = lib_data.index(b'\x00', ns_foff)
                ns_str = lib_data[ns_foff:ns_end].decode('utf-8', errors='replace')
            except Exception:
                continue
            if ns_str != class_ns: continue
            il2cpp_class_rva = class_base
            vtable_rva = class_base + 0x128
            print(f"[*] Il2CppClass* RVA = {il2cpp_class_rva:#x}  vtable RVA = {vtable_rva:#x}")
            break
        if vtable_rva: break

    if not vtable_rva:
        print("[!] vtable not found via ELF scan")

# ── output ────────────────────────────────────────────────────────────────────

result = {
    "target_class":     "CharacterInputController",
    "target_namespace": "SYBO.RunnerCore.Character",
    "target_field":     TARGET_FIELD,
    "found_in_class":   best['owner'] if best else None,
    "field_offset":     best['offset'] if best else None,
    "il2cpp_class_rva": il2cpp_class_rva,
    "vtable_rva":       vtable_rva,
    "metadata_version": version,
    "libil2cpp_size":   len(lib_data),
    "all_lane_fields":  lane_fields,
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] results:")
for k, v in result.items():
    if k == "all_lane_fields": continue
    print(f"    {k}: {hex(v) if isinstance(v, int) and v is not None else v}")
print(f"[*] written to {OUT}")