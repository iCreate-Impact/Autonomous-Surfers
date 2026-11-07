#!/usr/bin/env python3
"""
extract_offsets.py v8

Stop assuming pair indices. Identify every table by content fingerprint:
  - string table:    pair where data at offset[0] is b'\x00' (empty string first)
  - typedef table:   pair where sz % 88 == 0 and first entry name decodes as ASCII
  - fieldDef table:  pair where sz % 12 == 0, entry count ~ n_fields
  - fieldOffset table: pair of uint32[], count == n_fields, values look like offsets
  - Il2CppType[]:    pair where entries are 16 bytes, byte at +12 is IL2CPP_TYPE enum

Also: dump pair[8] and pair[24] type bytes to find the real Il2CppType array.
Dumps CharacterInputController and its 3 fields raw (using fieldDef + foff tables).
Dumps a sample of CharacterMotor fields with both foff candidates.

Usage:  py -3 extract_offsets.py base.apk
Output: offsets.json
"""

import sys, zipfile, struct, json

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "offsets.json"

TARGET_FIELD  = "_currentLaneIndex"
LANE_KEYWORDS = ["lane", "Lane"]

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

# count pairs
n_pairs = 0
for i in range(50):
    off, sz = pair(i)
    if off == 4 and sz <= 8:
        break
    n_pairs = i + 1

print(f"[*] metadata has ~{n_pairs} pairs")

# ── identify string table ─────────────────────────────────────────────────────
# The string table starts with a null byte (empty string at index 0).
# pair[2] is traditionally strings — verify or find it.

str_pair_idx = None
for pi in (2, 3, 4):
    off, sz = pair(pi)
    if sz > 0x10000 and meta_data[off] == 0:
        str_pair_idx = pi
        str_off = off
        print(f"[*] string table: pair[{pi}]  off={off:#x}  sz={sz:#x}")
        break
assert str_pair_idx is not None, "string table not found"

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── identify typedef table ────────────────────────────────────────────────────
# pair[19] traditionally. Each entry is 88 bytes, first field is a string index.
# Verify by checking first 10 entries decode to sensible names.

TD_SIZE = 88

def check_typedef_pair(pi):
    off, sz = pair(pi)
    if sz % TD_SIZE != 0: return False
    n = sz // TD_SIZE
    if n < 1000: return False
    ok = 0
    for i in range(min(20, n)):
        b = off + i * TD_SIZE
        try:
            ni, = struct.unpack_from("<I", meta_data, b)
            s = cstr(ni)
            if 0 < len(s) < 80 and all(0x20 <= ord(c) < 0x7f or c in '<>[]`_.$@' for c in s):
                ok += 1
        except Exception:
            pass
    return ok >= 15

type_pair_idx = None
for pi in (19, 18, 20, 17):
    if check_typedef_pair(pi):
        type_off, type_sz = pair(pi)
        n_types = type_sz // TD_SIZE
        type_pair_idx = pi
        print(f"[*] typedef table: pair[{pi}]  n_types={n_types}")
        break
assert type_pair_idx is not None, "typedef table not found"

FS_OFF     = 32
FC_OFF     = 64
PARENT_OFF = 20

# ── identify fieldDef table ───────────────────────────────────────────────────
# Each Il2CppFieldDefinition is 12 bytes: nameIndex(4) + typeIndex(4) + token(4)
# Count should be ~117148. Find by size.

FD_SIZE = 12
TARGET_FIELDS = 117148

fdef_pair_idx = None
for pi in range(n_pairs):
    off, sz = pair(pi)
    if sz % FD_SIZE != 0: continue
    n = sz // FD_SIZE
    if abs(n - TARGET_FIELDS) < 500:
        # verify: first entry name decodes
        try:
            ni, = struct.unpack_from("<I", meta_data, off)
            s = cstr(ni)
            if 0 < len(s) < 80:
                fdef_pair_idx = pi
                fdef_off = off
                fdef_sz  = sz
                n_fields = n
                print(f"[*] fieldDef table: pair[{pi}]  n_fields={n_fields}")
                break
        except Exception:
            pass

assert fdef_pair_idx is not None, "fieldDef table not found"

# ── identify field offset table ───────────────────────────────────────────────
# uint32[n_fields]. Values: 0x4xxxxxxx = static (high bit or 0x40000000 marker),
# small values = instance offset. Find the pair whose count == n_fields exactly.

foff_pair_idx = None
foff_off = None

for pi in range(n_pairs):
    off, sz = pair(pi)
    if sz != n_fields * 4: continue
    # sample: at least half should be < 0x10000 or have high bit set
    sane = 0
    for i in range(0, min(1000, n_fields), 10):
        v, = struct.unpack_from("<I", meta_data, off + i * 4)
        if v < 0x10000 or (v & 0x80000000):
            sane += 1
    if sane > 50:
        foff_pair_idx = pi
        foff_off = off
        print(f"[*] field offset table: pair[{pi}]  count={n_fields}")
        break

if foff_pair_idx is None:
    # relax: find pair whose count is n_fields ± 1 or whose sz is close
    print(f"[!] exact field offset table not found (n_fields={n_fields})")
    print(f"    looking for sz={n_fields*4:#x}...")
    for pi in range(n_pairs):
        off, sz = pair(pi)
        if abs(sz - n_fields * 4) < 16:
            print(f"    close: pair[{pi}]  sz={sz:#x}  diff={sz - n_fields*4}")

# ── identify Il2CppType[] ─────────────────────────────────────────────────────
# Entry = 16 bytes. parent token for MonoBehaviour = 32780 — must be valid index.
# Try pair[8] (n=66958) and pair[24] (n=61777) since both > 32780.
# Probe: type byte at +12 should be in IL2CPP_TYPE enum range 1..33.

KNOWN_TYPES = set(range(1, 34))

print(f"\n[*] probing Il2CppType[] candidates (need idx >= 32780)...")
itype_off = itype_sz = n_itypes = itype_pair_idx = 0

for pi in [8, 24, 5, 25, 11]:
    off, sz = pair(pi)
    n = sz // 16
    if n < 32781: continue
    # sample type bytes at +12
    sample_bytes = [meta_data[off + i*16 + 12] for i in range(0, min(50, n), 1)]
    in_range = sum(1 for b in sample_bytes if b in KNOWN_TYPES)
    print(f"  pair[{pi}]: n={n}  type_bytes[0:10]={sample_bytes[:10]}  "
          f"in_range={in_range}/50")
    if in_range >= 40 and not itype_off:
        itype_off, itype_sz, n_itypes, itype_pair_idx = off, sz, n, pi
        print(f"  → selected as Il2CppType[]")

# also try +8 and +13 as alternate type byte positions for the candidates above
if not itype_off:
    print(f"\n[*] standard +12 failed — trying alternate type byte offsets...")
    for pi in [8, 24, 5, 25]:
        off, sz = pair(pi)
        n = sz // 16
        if n < 32781: continue
        for type_byte_off in (8, 9, 12, 13, 14, 15):
            sample = [meta_data[off + i*16 + type_byte_off] for i in range(50)]
            in_range = sum(1 for b in sample if b in KNOWN_TYPES)
            if in_range >= 40:
                print(f"  pair[{pi}] type_byte@+{type_byte_off}: "
                      f"in_range={in_range}/50  "
                      f"sample={sample[:10]}")

# ── resolve parent token ──────────────────────────────────────────────────────

def parent_token_to_typedef(token, type_byte_off=12):
    if token < 0 or token == 0x7FFFFFFF or not n_itypes:
        return None
    if token >= n_itypes:
        return None
    b = itype_off + token * 16
    tb = meta_data[b + type_byte_off]
    if tb not in (0x11, 0x12):  # TYPE_VALUETYPE, TYPE_CLASS
        return None
    data, = struct.unpack_from("<Q", meta_data, b)
    return int(data) if data < n_types else None

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

if foff_off is not None:
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
else:
    field_to_typedef = {}
    known = 0
    print(f"[!] field offset table not found — skipping coverage")

# ── dump CIC fields ───────────────────────────────────────────────────────────

cic_td = next((td for td in all_types
               if td and td['name'] == 'CharacterInputController'
               and td['ns'] == 'SYBO.RunnerCore.Character'), None)

print(f"\n[*] CharacterInputController fields (raw fieldDef, no foff):")
if cic_td:
    fs = cic_td['field_start']
    fc = cic_td['field_count']
    print(f"  typedef_idx={cic_td['typedef_idx']}  "
          f"field_start={fs:#x}  field_count={fc}  "
          f"parent_tidx={cic_td['parent_tidx']}")
    if fs != 0xFFFFFFFF:
        for fi in range(fc):
            abs_fi = fs + fi
            b = fdef_off + abs_fi * FD_SIZE
            ni, tidx_fi, tok = struct.unpack_from("<III", meta_data, b)
            fname = cstr(ni)
            foff_val = "N/A"
            if foff_off:
                raw, = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
                foff_val = f"{raw:#010x} (inst={raw & 0x7FFFFFFF:#x}, static={bool(raw & 0x80000000)})"
            print(f"  [{abs_fi}] '{fname}'  typeIdx={tidx_fi}  token={tok}  foff={foff_val}")
    else:
        print(f"  field_start=0xFFFFFFFF — fields are in a base class")
        ptok = cic_td['parent_tidx']
        td_idx = parent_token_to_typedef(ptok)
        if td_idx is not None:
            pt = all_types[td_idx]
            print(f"  parent token {ptok} → [{td_idx}] "
                  f"{pt['ns']}.{pt['name']}  fc={pt['field_count']}")
        else:
            print(f"  parent token {ptok} still unresolvable")

# ── dump CharacterMotor first 10 fields with both foff candidates ─────────────

motor_td = next((td for td in all_types
                 if td and td['name'] == 'CharacterMotor'
                 and td['ns'] == 'SYBO.RunnerCore.Character'), None)

if motor_td and motor_td['field_start'] != 0xFFFFFFFF:
    fs = motor_td['field_start']
    print(f"\n[*] CharacterMotor first 10 fields  (field_start={fs}):")
    # find foff candidates: any pair whose n*4 covers abs_fi range
    foff_candidates = []
    for pi in range(n_pairs):
        off, sz = pair(pi)
        if sz % 4 != 0: continue
        n = sz // 4
        if n >= fs + 10:
            foff_candidates.append((pi, off, n))

    for fi in range(min(10, motor_td['field_count'])):
        abs_fi = fs + fi
        b = fdef_off + abs_fi * FD_SIZE
        ni, tidx_fi, tok = struct.unpack_from("<III", meta_data, b)
        fname = cstr(ni)
        vals = []
        for pi, coff, cn in foff_candidates[:6]:
            raw, = struct.unpack_from("<I", meta_data, coff + abs_fi * 4)
            vals.append(f"p{pi}={raw:#x}")
        print(f"  [{abs_fi}] '{fname}'  {' '.join(vals)}")

# ── scan ALL fields for lane-related names ────────────────────────────────────

if foff_off is not None:
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
            'field_name': fname, 'abs_fi': abs_fi, 'offset': foff,
            'static': static, 'sane': sane, 'owner': owner_name,
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
else:
    lane_fields = []
    target_hits = []
    print(f"\n[!] skipping lane scan (no field offset table)")

# ── output ────────────────────────────────────────────────────────────────────

result = {
    "target_class":     "CharacterInputController",
    "target_namespace": "SYBO.RunnerCore.Character",
    "target_field":     TARGET_FIELD,
    "found_in_class":   None,
    "field_name_used":  None,
    "field_offset":     None,
    "il2cpp_class_rva": None,
    "vtable_rva":       None,
    "metadata_version": version,
    "libil2cpp_size":   len(lib_data),
    "pairs_identified": {
        "str":    str_pair_idx,
        "typedef": type_pair_idx,
        "fdef":   fdef_pair_idx,
        "foff":   foff_pair_idx,
        "itype":  itype_pair_idx if itype_off else None,
    },
    "tidx_coverage":    known,
    "all_lane_fields":  lane_fields,
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] pairs identified: {result['pairs_identified']}")
print(f"[*] written to {OUT}")