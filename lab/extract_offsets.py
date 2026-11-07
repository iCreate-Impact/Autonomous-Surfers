#!/usr/bin/env python3
"""
extract_offsets.py v5
- dumps raw Il2CppTypeDefinition bytes for known classes so you can
  manually identify field_start / field_count / parent offsets
- also dumps the full CharacterInputController typedef hex
- tries multiple TD_SIZE candidates (88, 96, 104) in case v31 grew the struct
- brute-force field scan with owner resolution
- writes offsets.json

Usage:  py -3 extract_offsets.py base.apk
"""

import sys, zipfile, struct, json, textwrap

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

def pair(idx):
    return struct.unpack_from("<II", meta_data, 8 + idx * 8)

str_off, _        = pair(2)
type_off, type_sz = pair(19)
fdef_off, fdef_sz = pair(10)
foff_off, foff_sz = pair(11)
FD_SIZE = 12

n_fields = fdef_sz // FD_SIZE
print(f"[*] n_fields={n_fields}")

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── probe TD_SIZE ─────────────────────────────────────────────────────────────
# Try TD sizes 88, 96, 104. For each, check that
#   cstr(type_off + 0) is a valid short string (the first type's name)
# and that scanning the first 200 typedefs produces sensible names.

print("\n[*] probing TD_SIZE...")
for td_size_cand in (88, 96, 104):
    n_cand = type_sz // td_size_cand
    try:
        name0, = struct.unpack_from("<I", meta_data, type_off)
        ns0,   = struct.unpack_from("<I", meta_data, type_off + 4)
        n0 = cstr(name0)
        ns0s = cstr(ns0)
        # count how many of the first 200 names decode as ASCII printable
        ok = 0
        for i in range(min(200, n_cand)):
            b = type_off + i * td_size_cand
            ni, = struct.unpack_from("<I", meta_data, b)
            try:
                s = cstr(ni)
                if all(0x20 <= ord(c) < 0x7f or c in '<>[]`_.$@' for c in s):
                    ok += 1
            except Exception:
                pass
        print(f"  TD_SIZE={td_size_cand}: n_types={n_cand}  first='{n0}'  ns='{ns0s}'  ascii_ok={ok}/200")
    except Exception as e:
        print(f"  TD_SIZE={td_size_cand}: error {e}")

# ── pick TD_SIZE and read all types ───────────────────────────────────────────
# Default: 88 (most likely correct based on probe above). Edit if needed.
TD_SIZE = 88
n_types = type_sz // TD_SIZE
print(f"\n[*] using TD_SIZE={TD_SIZE}  n_types={n_types}")

# ── dump raw typedef hex for CharacterInputController and 3 known classes ─────
# This is the key diagnostic. We find them by name and dump 96 bytes raw
# so you can read off field_start, field_count, parent at the right offsets.

PROBE_CLASSES = [
    # (name, namespace) — these are common Unity types with known field counts
    ("MonoBehaviour",            "UnityEngine"),
    ("GameObject",               "UnityEngine"),
    ("CharacterInputController", "SYBO.RunnerCore.Character"),
    ("CharacterMotor",           "SYBO.RunnerCore.Character"),
    ("CharacterAbilityRunner",   "SYBO.RunnerCore.Character"),
]

def find_typedef_raw(search_name, search_ns):
    for i in range(n_types):
        b = type_off + i * TD_SIZE
        try:
            ni, nsi = struct.unpack_from("<II", meta_data, b)
            if cstr(ni) == search_name and cstr(nsi) == search_ns:
                return i, b
        except Exception:
            pass
    return None, None

print("\n[*] raw typedef hex dumps (96 bytes each):")
print("    offset  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f")
for (cls_name, cls_ns) in PROBE_CLASSES:
    td_idx, td_base = find_typedef_raw(cls_name, cls_ns)
    if td_base is None:
        print(f"\n  {cls_ns}.{cls_name}: NOT FOUND")
        continue
    raw = meta_data[td_base : td_base + 96]
    print(f"\n  [{td_idx}] {cls_ns}.{cls_name}:")
    for row in range(0, 96, 16):
        chunk = raw[row:row+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk[:8])
        hex_part += '  ' + ' '.join(f'{b:02x}' for b in chunk[8:])
        # also decode as uint32 array for easy reading
        u32s = []
        for j in range(0, min(16, len(chunk)), 4):
            v, = struct.unpack_from("<I", chunk, j)
            u32s.append(f"{v:#010x}")
        print(f"    +{row:02x}  {hex_part:<48}  {' '.join(u32s)}")

# ── MANUAL STEP hint ──────────────────────────────────────────────────────────
# After running, look at the hex dumps and find:
#   - field_start: a uint32 that equals the known first field index of the class
#   - field_count: a uint16 or uint32 matching the known field count
#   - parentIdx: for MonoBehaviour the parent should be Behaviour (or Component)
#
# Update FS_OFF, FC_OFF, PARENT_OFF below and re-run to get real offsets.
# If you don't know the field counts, grep the dump for a class you do know,
# like GameObject (Unity source says it has ~5 fields in older versions).

# ── configurable offsets (edit these after reading the hex dump) ──────────────
FS_OFF     = 32   # field_start offset within typedef
FC_OFF     = 68   # field_count offset within typedef  (uint16)
PARENT_OFF = 20   # parentIdx offset within typedef    (int32, typeIndex)

print(f"\n[*] using FS_OFF={FS_OFF}  FC_OFF={FC_OFF}  PARENT_OFF={PARENT_OFF}")
print(f"    (edit these at the top of the script after reading the hex dump)")

# ── build typedef table ───────────────────────────────────────────────────────

all_types = []
for i in range(n_types):
    b = type_off + i * TD_SIZE
    try:
        name_idx, ns_idx    = struct.unpack_from("<II", meta_data, b)
        field_start,        = struct.unpack_from("<I",  meta_data, b + FS_OFF)
        field_count,        = struct.unpack_from("<H",  meta_data, b + FC_OFF)
        parent_type_idx,    = struct.unpack_from("<i",  meta_data, b + PARENT_OFF)
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

# also report the top 5 largest classes by field_count (sanity check)
top5 = sorted([td for td in all_types if td], key=lambda t: t['field_count'], reverse=True)[:5]
print(f"[*] top 5 classes by field_count:")
for td in top5:
    ns_name = f"{td['ns']}.{td['name']}" if td['ns'] else td['name']
    print(f"    {ns_name}  field_count={td['field_count']}  field_start={td['field_start']}")

# ── probe typeIndex table ─────────────────────────────────────────────────────

tidx_off = tidx_sz = n_tidx = 0
for probe_i in range(20, 35):
    off, sz = pair(probe_i)
    n = sz // 4
    if n < 100:
        continue
    sample = min(50, n)
    if all(struct.unpack_from("<I", meta_data, off + j*4)[0] < n_types for j in range(sample)):
        tidx_off, tidx_sz, n_tidx = off, sz, n
        print(f"[*] typeIndex table: pair[{probe_i}]  entries={n_tidx}")
        break

if not n_tidx:
    print("[!] typeIndex table not found — parent chain disabled")

def tidx_to_typedef(tidx):
    if not n_tidx or tidx < 0 or tidx >= n_tidx:
        return None
    val, = struct.unpack_from("<I", meta_data, tidx_off + tidx * 4)
    return val if val < n_types else None

# ── scan ALL fields for lane-related names ────────────────────────────────────

print(f"\n[*] scanning all {n_fields} fields for lane-related names...")
lane_fields = []
target_hits = []

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
        td = all_types[owner_td_idx]
        owner_name = f"{td['ns']}.{td['name']}" if td['ns'] else td['name']
    else:
        owner_name = "<unknown>"

    sane = 0x10 <= foff <= 0x800 and not static
    entry = {
        'field_name': fname,
        'abs_fi':     abs_fi,
        'offset':     foff,
        'static':     static,
        'sane':       sane,
        'owner':      owner_name,
    }
    lane_fields.append(entry)
    if is_target:
        target_hits.append(entry)

print(f"[*] found {len(lane_fields)} lane-related field(s):")
for e in lane_fields:
    marker = " ← EXACT" if e['field_name'] == TARGET_FIELD else ""
    sane_s = " [sane]" if e['sane'] else ""
    print(f"    [{e['abs_fi']}] {e['owner']}.{e['field_name']}  "
          f"offset={e['offset']:#x}  static={e['static']}{sane_s}{marker}")

# ── parent chain walk ─────────────────────────────────────────────────────────

print(f"\n[*] walking parent chain of CharacterInputController:")
cic = next((td for td in all_types
            if td and td['name'] == 'CharacterInputController'
            and td['ns'] == 'SYBO.RunnerCore.Character'), None)

if not cic:
    print("[!] CharacterInputController not found")
else:
    visited = set()
    cur = cic
    depth = 0
    while cur:
        if cur['typedef_idx'] in visited:
            print(f"  [depth {depth}] circular, stopping")
            break
        visited.add(cur['typedef_idx'])
        ns_name = f"{cur['ns']}.{cur['name']}" if cur['ns'] else cur['name']
        print(f"  [depth {depth}] {ns_name}  "
              f"fields={cur['field_count']}  "
              f"field_start={cur['field_start']}  "
              f"parent_tidx={cur['parent_tidx']}")
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
                print(f"    [{abs_fi}] '{fname}'  offset={foff:#x}  static={static}{marker}")
            except Exception as ex:
                print(f"    [{abs_fi}] error: {ex}")

        pidx = cur['parent_tidx']
        if pidx < 0 or pidx == 0x7FFFFFFF:
            print(f"  no parent, stopping")
            break
        td_idx = tidx_to_typedef(pidx)
        if td_idx is None:
            if 0 <= pidx < n_types and all_types[pidx]:
                print(f"  typeIndex {pidx} out of tidx table — trying as direct typedef")
                td_idx = pidx
            else:
                print(f"  parent pidx={pidx} unresolvable, stopping")
                break
        cur = all_types[td_idx] if td_idx < len(all_types) else None
        depth += 1
        if depth > 20:
            print("  [depth limit]")
            break

# ── pick best ────────────────────────────────────────────────────────────────

best = None
if target_hits:
    cands = [e for e in target_hits if e['sane']]
    best = cands[0] if cands else target_hits[0]
elif lane_fields:
    priority_names = ('currentLane', 'laneIndex', '_currentLaneIndex')
    cands = [e for e in lane_fields if e['sane'] and e['owner'] != '<unknown>'
             and e['field_name'] in priority_names]
    if not cands:
        cands = [e for e in lane_fields if e['sane'] and e['owner'] != '<unknown>']
    if not cands:
        cands = [e for e in lane_fields if e['sane']]
    best = cands[0] if cands else None

if best:
    print(f"\n[*] best candidate: {best['owner']}.{best['field_name']}  offset={best['offset']:#x}")
else:
    print("\n[!] no usable lane field found")

# ── ELF vtable scan ───────────────────────────────────────────────────────────

vtable_rva = None
il2cpp_class_rva = None

if best and best['owner'] not in ('<unknown>', ''):
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
    "target_class":        "CharacterInputController",
    "target_namespace":    "SYBO.RunnerCore.Character",
    "target_field":        TARGET_FIELD,
    "found_in_class":      best['owner']        if best else None,
    "field_name_used":     best['field_name']   if best else None,
    "field_offset":        best['offset']       if best else None,
    "il2cpp_class_rva":    il2cpp_class_rva,
    "vtable_rva":          vtable_rva,
    "metadata_version":    version,
    "libil2cpp_size":      len(lib_data),
    "field_layout_probe":  {"TD_SIZE": TD_SIZE, "fs_off": FS_OFF, "fc_off": FC_OFF, "parent_off": PARENT_OFF},
    "tidx_coverage":       known,
    "all_lane_fields":     lane_fields,
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] results:")
for k, v in result.items():
    if k == "all_lane_fields": continue
    print(f"    {k}: {hex(v) if isinstance(v, int) and v is not None else v}")
print(f"[*] written to {OUT}")