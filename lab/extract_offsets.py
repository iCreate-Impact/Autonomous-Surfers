#!/usr/bin/env python3
"""
extract_offsets.py v8b

Hardcodes confirmed pair indices from the dump rather than probing,
since the probe assumptions broke on v31.

Confirmed from previous dump:
  pair[2]  = string table        off=0xcd54c   sz=0x257150
  pair[10] = fieldDef            off=0x928550  sz=0x157350  → 87861 entries × 12 = wait, 0x157350/12 = 87900? no.
             actually 0x157350 / 12 = 87836.0 — not clean. let's check /4 and /8 too.
  pair[11] = fieldOffsets        off=0xa7f8a0  sz=0x1008a8  → 0x1008a8/4 = 263332? no.
  pair[19] = typeDef             off=0xc86d68  sz=0x1b6218  → 0x1b6218/88 = 20381? close to 20393.

We'll re-derive n_fields from fdef and match foff by exact count.
Prints first byte at each pair offset so we can verify string table.

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

# ── print first byte and size for every pair so we can see the layout ─────────
print(f"\n[*] pair table (off, sz, first_byte, sz/88, sz/12, sz/4):")
for i in range(35):
    off, sz = pair(i)
    if sz == 0: continue
    if off >= len(meta_data): continue
    fb = meta_data[off] if off < len(meta_data) else 0xFF
    print(f"  pair[{i:2d}]: off={off:#010x}  sz={sz:#010x}  "
          f"first_byte={fb:#04x}  "
          f"/88={sz//88:6d}  /12={sz//12:6d}  /4={sz//4:8d}")

# ── string table: find pair where first byte == 0 and sz is large ─────────────
print(f"\n[*] identifying string table (first_byte==0, sz>0x50000)...")
str_off = str_sz = str_pi = None
for i in range(35):
    off, sz = pair(i)
    if sz < 0x50000: continue
    if off >= len(meta_data): continue
    if meta_data[off] == 0:
        str_off, str_sz, str_pi = off, sz, i
        print(f"  pair[{i}]: off={off:#x}  sz={sz:#x}  ← string table")
        break

if str_off is None:
    # relax: biggest pair whose first byte is 0
    biggest = max(
        ((i, off, sz) for i in range(35)
         for (off, sz) in [pair(i)]
         if sz > 0 and off < len(meta_data) and meta_data[off] == 0),
        key=lambda t: t[2], default=None)
    if biggest:
        str_pi, str_off, str_sz = biggest
        print(f"  relaxed → pair[{str_pi}]: off={str_off:#x}  sz={str_sz:#x}")

assert str_off is not None, "could not find string table"

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── typedef table: pair where sz%88==0 and names decode ───────────────────────
print(f"\n[*] identifying typedef table...")
type_off = type_sz = type_pi = None
for i in range(35):
    off, sz = pair(i)
    if sz % TD_SIZE != 0: continue
    n = sz // TD_SIZE
    if n < 5000 or n > 100000: continue
    ok = 0
    for j in range(min(20, n)):
        b = off + j * TD_SIZE
        try:
            ni, = struct.unpack_from("<I", meta_data, b)
            s = cstr(ni)
            if 0 < len(s) < 100:
                ok += 1
        except Exception:
            pass
    if ok >= 15:
        type_off, type_sz, type_pi = off, sz, i
        n_types = sz // TD_SIZE
        print(f"  pair[{i}]: n_types={n_types}  ← typedef table")
        break

assert type_off is not None, "typedef table not found"
n_types = type_sz // TD_SIZE

# ── fieldDef table ─────────────────────────────────────────────────────────────
# Il2CppFieldDefinition v31: nameIdx(4) + typeIdx(4) + token(4) = 12 bytes
# Count should be ~117148. The pair from the previous dump was pair[10].
# Also try pairs where sz/12 is close to 117148.

print(f"\n[*] identifying fieldDef table (target ~117148 entries × 12 bytes)...")
fdef_off = fdef_sz = fdef_pi = None
n_fields = None
for i in range(35):
    off, sz = pair(i)
    if sz % 12 != 0: continue
    n = sz // 12
    if abs(n - 117148) > 2000: continue
    try:
        ni, = struct.unpack_from("<I", meta_data, off)
        s = cstr(ni)
        if 0 < len(s) < 100:
            fdef_off, fdef_sz, fdef_pi = off, sz, i
            n_fields = n
            print(f"  pair[{i}]: n_fields={n_fields}  ← fieldDef table")
            break
    except Exception:
        pass

if fdef_off is None:
    print(f"  [!] not found by size+name — trying pair[10] directly")
    off, sz = pair(10)
    fdef_off, fdef_sz, fdef_pi = off, sz, 10
    n_fields = sz // 12
    print(f"  pair[10]: off={off:#x}  sz={sz:#x}  n={n_fields}")

FD_SIZE = 12

# ── field offset table: sz must equal n_fields * 4 ────────────────────────────
print(f"\n[*] identifying field offset table (need sz=={n_fields}*4={n_fields*4:#x})...")
foff_off = foff_pi = None
for i in range(35):
    off, sz = pair(i)
    if sz == n_fields * 4:
        # verify: sample offsets look like instance offsets or static markers
        sane = 0
        for j in range(0, min(2000, n_fields), 20):
            v, = struct.unpack_from("<I", meta_data, off + j * 4)
            if v < 0x10000 or (v & 0x40000000) or (v & 0x80000000):
                sane += 1
        print(f"  pair[{i}]: sz matches  sane_sample={sane}/100")
        if sane > 60:
            foff_off, foff_pi = off, i
            print(f"  pair[{i}] ← field offset table")
            break

if foff_off is None:
    print(f"  [!] exact match not found — closest pairs:")
    target = n_fields * 4
    for i in range(35):
        off, sz = pair(i)
        if abs(sz - target) < target * 0.02:
            print(f"    pair[{i}]: sz={sz:#x}  diff={sz-target:+d}")

# ── print first 20 fields of CharacterMotor with every size-matching foff ─────
# This identifies the real foff table regardless of pair index.
print(f"\n[*] CharacterMotor field × foff-candidate cross-table:")

# build typedef table minimally
all_types = []
for i in range(n_types):
    b = type_off + i * TD_SIZE
    try:
        name_idx, ns_idx = struct.unpack_from("<II", meta_data, b)
        field_start,     = struct.unpack_from("<I",  meta_data, b + FS_OFF)
        field_count,     = struct.unpack_from("<H",  meta_data, b + FC_OFF)
        parent_tidx,     = struct.unpack_from("<i",  meta_data, b + PARENT_OFF)
        all_types.append({
            'name': cstr(name_idx), 'ns': cstr(ns_idx),
            'field_start': field_start, 'field_count': field_count,
            'parent_tidx': parent_tidx, 'typedef_idx': i,
        })
    except Exception:
        all_types.append(None)

motor_td = next((td for td in all_types
                 if td and td['name'] == 'CharacterMotor'
                 and td['ns'] == 'SYBO.RunnerCore.Character'), None)

cic_td = next((td for td in all_types
               if td and td['name'] == 'CharacterInputController'
               and td['ns'] == 'SYBO.RunnerCore.Character'), None)

# collect all pairs that could be foff (sz/4 >= motor field_start + field_count)
foff_candidates = []
if motor_td and motor_td['field_start'] != 0xFFFFFFFF:
    need = motor_td['field_start'] + motor_td['field_count']
    for i in range(35):
        off, sz = pair(i)
        if sz % 4 == 0 and sz // 4 >= need:
            foff_candidates.append((i, off, sz // 4))

    fs = motor_td['field_start']
    fc = motor_td['field_count']
    print(f"  CharacterMotor: field_start={fs}  field_count={fc}")
    print(f"  {'field_name':<35} " +
          "  ".join(f"p{pi:02d}" for pi, _, _ in foff_candidates[:8]))
    for fi in range(min(20, fc)):
        abs_fi = fs + fi
        b = fdef_off + abs_fi * FD_SIZE
        try:
            ni, = struct.unpack_from("<I", meta_data, b)
            fname = cstr(ni)
        except Exception:
            fname = f"<err@{abs_fi}>"
        vals = []
        for pi, coff, cn in foff_candidates[:8]:
            raw, = struct.unpack_from("<I", meta_data, coff + abs_fi * 4)
            # show as hex, mark if sane instance offset
            mark = "*" if 0x10 <= (raw & 0x7FFFFFFF) <= 0x1000 else " "
            vals.append(f"{mark}{raw:#010x}")
        print(f"  {fname:<35} " + "  ".join(vals))

# ── CIC summary ───────────────────────────────────────────────────────────────
print(f"\n[*] CharacterInputController:")
if cic_td:
    print(f"  field_start={cic_td['field_start']:#x}  "
          f"field_count={cic_td['field_count']}  "
          f"parent_tidx={cic_td['parent_tidx']}")
    if cic_td['field_start'] != 0xFFFFFFFF and foff_off:
        for fi in range(cic_td['field_count']):
            abs_fi = cic_td['field_start'] + fi
            b = fdef_off + abs_fi * FD_SIZE
            ni, tidx_fi, tok = struct.unpack_from("<III", meta_data, b)
            fname = cstr(ni)
            raw, = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
            print(f"  [{abs_fi}] '{fname}'  raw_foff={raw:#010x}  "
                  f"inst={raw & 0x7FFFFFFF:#x}  static={bool(raw & 0x80000000)}")

# ── output stub ───────────────────────────────────────────────────────────────
result = {
    "metadata_version": version,
    "pairs_identified": {
        "str":    str_pi,
        "typedef": type_pi,
        "fdef":   fdef_pi,
        "foff":   foff_pi,
    },
    "n_types":  n_types,
    "n_fields": n_fields,
}
with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] pairs identified: {result['pairs_identified']}")
print(f"[*] written to {OUT}")