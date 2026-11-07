#!/usr/bin/env python3
"""
extract_offsets.py v7

Key fix: parentIdx is an index into Il2CppType[] (pair[13]),
not into the typedef table or the typeIndex table.
Il2CppType layout (ARM64, v27-v31):
  +0x00  uint64 data   (union: for TYPE_CLASS/TYPE_VALUETYPE = typedef index)
  +0x08  uint32 attrs
  +0x0c  uint8  type   (IL2CPP_TYPE_* enum)
  +0x0d  uint8  num_mods
  +0x0e  uint8  byref
  +0x0f  uint8  pinned
Total = 16 bytes per entry.

TYPE_CLASS      = 0x12
TYPE_VALUETYPE  = 0x11

Usage:  py -3 extract_offsets.py base.apk
Output: offsets.json
"""

import sys, zipfile, struct, json

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "offsets.json"

TARGET_FIELD  = "_currentLaneIndex"
LANE_KEYWORDS = ["lane", "Lane"]

TD_SIZE    = 88
FS_OFF     = 32
FC_OFF     = 64
PARENT_OFF = 20

TYPE_CLASS      = 0x12
TYPE_VALUETYPE  = 0x11
IL2CPP_TYPE_SIZE = 16

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

str_off,  _        = pair(2)
type_off, type_sz  = pair(19)
fdef_off, fdef_sz  = pair(10)
foff_off, foff_sz  = pair(11)
FD_SIZE = 12

n_types  = type_sz  // TD_SIZE
n_fields = fdef_sz  // FD_SIZE
print(f"[*] n_types={n_types}  n_fields={n_fields}")

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── locate Il2CppType[] array ─────────────────────────────────────────────────
# Try pair indices 13, 14, 15, 16 — look for one whose entry count is
# larger than n_types (it must be, since it includes constructed types)
# and where entry[0].type byte is a known IL2CPP_TYPE value.

KNOWN_TYPES = set(range(0x01, 0x22))  # IL2CPP_TYPE_VOID..IL2CPP_TYPE_INTERNAL

itype_off = itype_sz = n_itypes = itype_pair_idx = 0

print(f"\n[*] probing Il2CppType[] array location...")
for pi in range(12, 22):
    off, sz = pair(pi)
    if sz == 0:
        continue
    n = sz // IL2CPP_TYPE_SIZE
    if n < n_types:
        continue
    # sample first 10 entries: type byte must be a known value
    ok = 0
    for i in range(min(10, n)):
        type_byte = meta_data[off + i * IL2CPP_TYPE_SIZE + 12]
        if type_byte in KNOWN_TYPES:
            ok += 1
    if ok >= 8:
        itype_off, itype_sz, n_itypes, itype_pair_idx = off, sz, n, pi
        print(f"[*] Il2CppType[]: pair[{pi}]  n={n_itypes}  "
              f"(first type bytes: "
              f"{[meta_data[off+i*IL2CPP_TYPE_SIZE+12] for i in range(5)]})")
        break

if not n_itypes:
    print("[!] Il2CppType[] not found — dumping pair table for manual inspection:")
    for pi in range(0, 35):
        off, sz = pair(pi)
        if sz == 0: continue
        print(f"  pair[{pi}]: off={off:#x}  sz={sz:#x}  n_as_16={sz//16}")

def parent_token_to_typedef(token):
    """Resolve parentIdx as an index into Il2CppType[]."""
    if token < 0 or token == 0x7FFFFFFF or not n_itypes:
        return None
    if token >= n_itypes:
        return None
    b = itype_off + token * IL2CPP_TYPE_SIZE
    type_byte = meta_data[b + 12]
    if type_byte not in (TYPE_CLASS, TYPE_VALUETYPE):
        return None
    # data field (uint64) = typedef index for class/valuetype
    data, = struct.unpack_from("<Q", meta_data, b)
    if data >= n_types:
        return None
    return int(data)

# verify: MonoBehaviour parent should resolve to Behaviour
mono_idx = None
for i in range(n_types):
    b = type_off + i * TD_SIZE
    try:
        ni, nsi = struct.unpack_from("<II", meta_data, b)
        if cstr(ni) == 'MonoBehaviour' and cstr(nsi) == 'UnityEngine':
            mono_idx = i
            break
    except Exception:
        pass

if mono_idx is not None:
    mb = type_off + mono_idx * TD_SIZE
    ptok, = struct.unpack_from("<i", meta_data, mb + PARENT_OFF)
    resolved = parent_token_to_typedef(ptok)
    if resolved is not None:
        rb = type_off + resolved * TD_SIZE
        rni, rnsi = struct.unpack_from("<II", meta_data, rb)
        print(f"[*] verify: MonoBehaviour parent token={ptok} → "
              f"typedef[{resolved}] = {cstr(rnsi)}.{cstr(rni)}")
    else:
        print(f"[!] MonoBehaviour parent token={ptok} still unresolvable — "
              f"Il2CppType[] probe may be wrong")

# ── build typedef table ───────────────────────────────────────────────────────

print(f"\n[*] building typedef table...")
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
    if td is None or td['field_count'] == 0 or td['field_start'] == 0xFFFFFFFF:
        continue
    for fi in range(td['field_count']):
        abs_fi = td['field_start'] + fi
        if 0 <= abs_fi < n_fields and abs_fi not in field_to_typedef:
            field_to_typedef[abs_fi] = td['typedef_idx']

known = len(field_to_typedef)
print(f"[*] field_to_typedef coverage: {known}/{n_fields} ({100*known/n_fields:.1f}%)")

top5 = sorted([td for td in all_types if td and td['field_start'] != 0xFFFFFFFF],
              key=lambda t: t['field_count'], reverse=True)[:5]
print(f"[*] top 5 classes by field_count (excluding sentinel):")
for td in top5:
    ns_name = f"{td['ns']}.{td['name']}" if td['ns'] else td['name']
    print(f"    {ns_name}  fc={td['field_count']}  fs={td['field_start']}")

# ── parent chain walk ─────────────────────────────────────────────────────────

def walk_chain(start_td, label):
    print(f"\n[*] parent chain of {label}:")
    if start_td is None:
        print("  NOT FOUND")
        return
    visited = set()
    cur = start_td
    depth = 0
    while cur:
        if cur['typedef_idx'] in visited:
            print(f"  [depth {depth}] circular, stopping")
            break
        visited.add(cur['typedef_idx'])
        ns_name = f"{cur['ns']}.{cur['name']}" if cur['ns'] else cur['name']
        fs = cur['field_start']
        fc = cur['field_count']
        fs_str = hex(fs) if fs != 0xFFFFFFFF else "0xFFFFFFFF(none)"
        print(f"  [depth {depth}] [{cur['typedef_idx']}] {ns_name}  "
              f"fields={fc}  field_start={fs_str}")

        if fc > 0 and fs != 0xFFFFFFFF:
            for fi in range(fc):
                abs_fi = fs + fi
                if abs_fi >= n_fields:
                    print(f"    [{abs_fi}] out of range")
                    continue
                b = fdef_off + abs_fi * FD_SIZE
                try:
                    name_idx, = struct.unpack_from("<I", meta_data, b)
                    fname     = cstr(name_idx)
                    raw,      = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
                    foff      = raw & 0x7FFFFFFF
                    static    = bool(raw & 0x80000000)
                    marker    = " ← TARGET" if fname == TARGET_FIELD else ""
                    lane_m    = " [lane]" if any(k in fname for k in LANE_KEYWORDS) else ""
                    print(f"    [{abs_fi}] '{fname}'  offset={foff:#x}  "
                          f"static={static}{lane_m}{marker}")
                except Exception as ex:
                    print(f"    [{abs_fi}] error: {ex}")

        ptok = cur['parent_tidx']
        if ptok < 0 or ptok == 0x7FFFFFFF:
            print(f"  → no parent, done")
            break
        td_idx = parent_token_to_typedef(ptok)
        if td_idx is None:
            print(f"  → parent token {ptok} unresolvable, stopping")
            break
        cur = all_types[td_idx] if td_idx < len(all_types) else None
        depth += 1
        if depth > 25:
            print("  [depth limit]")
            break

cic_td = next((td for td in all_types
               if td and td['name'] == 'CharacterInputController'
               and td['ns'] == 'SYBO.RunnerCore.Character'), None)
walk_chain(cic_td, "CharacterInputController")

# also walk CharacterMotor — it had real fields and laneDirection is in RunnerCore
motor_td = next((td for td in all_types
                 if td and td['name'] == 'CharacterMotor'
                 and td['ns'] == 'SYBO.RunnerCore.Character'), None)
walk_chain(motor_td, "CharacterMotor")

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

    sane = 0x10 <= foff <= 0x2000 and not static
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
    sane_s = " [sane]"  if e['sane'] else ""
    print(f"    [{e['abs_fi']}] {e['owner']}.{e['field_name']}  "
          f"offset={e['offset']:#x}{sane_s}{marker}")

# ── pick best ─────────────────────────────────────────────────────────────────

best = None
if target_hits:
    cands = [e for e in target_hits if e['sane']]
    best = cands[0] if cands else target_hits[0]
elif lane_fields:
    priority = ('currentLane', 'laneIndex', '_currentLaneIndex')
    for pool in (
        [e for e in lane_fields if e['sane'] and e['owner'] != '<unknown>'
         and e['field_name'] in priority],
        [e for e in lane_fields if e['sane'] and e['owner'] != '<unknown>'],
        [e for e in lane_fields if e['sane']],
    ):
        if pool:
            best = pool[0]
            break

if best:
    print(f"\n[*] best candidate: {best['owner']}.{best['field_name']}  "
          f"offset={best['offset']:#x}")
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
    hits, pos = [], 0
    while True:
        p = lib_data.find(needle, pos)
        if p == -1: break
        rva = foff_to_rva(p)
        if rva: hits.append((p, rva))
        pos = p + 1
    print(f"\n[*] '{class_simple}' ELF string hits: {len(hits)}")

    for sfoff, srva in hits:
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
            vtable_rva       = class_base + 0x128
            print(f"[*] Il2CppClass* RVA = {il2cpp_class_rva:#x}  "
                  f"vtable RVA = {vtable_rva:#x}")
            break
        if vtable_rva: break

    if not vtable_rva:
        print("[!] vtable not found via ELF scan")

# ── output ────────────────────────────────────────────────────────────────────

result = {
    "target_class":     "CharacterInputController",
    "target_namespace": "SYBO.RunnerCore.Character",
    "target_field":     TARGET_FIELD,
    "found_in_class":   best['owner']      if best else None,
    "field_name_used":  best['field_name'] if best else None,
    "field_offset":     best['offset']     if best else None,
    "il2cpp_class_rva": il2cpp_class_rva,
    "vtable_rva":       vtable_rva,
    "metadata_version": version,
    "libil2cpp_size":   len(lib_data),
    "field_layout":     {"TD_SIZE": TD_SIZE, "FS_OFF": FS_OFF,
                         "FC_OFF": FC_OFF, "PARENT_OFF": PARENT_OFF,
                         "itype_pair": itype_pair_idx, "n_itypes": n_itypes},
    "tidx_coverage":    known,
    "all_lane_fields":  lane_fields,
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] results:")
for k, v in result.items():
    if k == "all_lane_fields": continue
    print(f"    {k}: {hex(v) if isinstance(v, int) and v is not None else v}")
print(f"[*] written to {OUT}")