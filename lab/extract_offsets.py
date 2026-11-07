#!/usr/bin/env python3
"""
extract_offsets.py v9

Confirmed from pair table analysis:
  str_off  = pair[1]  off=0x2c4e0  (first_byte=0x00, v31 string table)
  type_off = pair[19] off=0xc86d68 sz=0x1b6218 /88=20393
  fdef_off = pair[10] off=0x928550 sz=0x157350

Key hypothesis: v31 Il2CppFieldDefinition is 16 bytes, not 12:
  nameIdx   uint32  +0
  typeIdx   uint32  +4
  token     uint32  +8
  offset    uint32  +12   ← field offset baked in, no separate table
  → n_fields = 0x157350/16 = 87861

Alternative: still 12 bytes, separate foff table missing/elsewhere.

This version:
  1. tries both 12-byte and 16-byte fieldDef interpretations
  2. for each: dumps CharacterMotor first 20 fields with their offsets
  3. whichever gives sane offsets for real field names is correct
  4. also dumps pair[0] and pair[1] first 64 bytes to confirm string table

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

# ── confirmed from pair dump ──────────────────────────────────────────────────
# pair[1]: first_byte=0x00, sz=0xa106c — string table (starts with null)
# pair[2]: first_byte=0x41, sz=0x257150 — NOT string table (starts with 'A')
# pair[10]: sz=0x157350 — fieldDef (divides by 12=117148 and 16=87861)
# pair[19]: sz=0x1b6218 /88=20393 — typedef table

STR_PI  = 1
TYPE_PI = 19
FDEF_PI = 10

str_off,  str_sz  = pair(STR_PI)
type_off, type_sz = pair(TYPE_PI)
fdef_off, fdef_sz = pair(FDEF_PI)

n_types = type_sz // TD_SIZE
print(f"\n[*] tables: str=pair[{STR_PI}] off={str_off:#x}, "
      f"typedef=pair[{TYPE_PI}] n={n_types}, "
      f"fdef=pair[{FDEF_PI}] sz={fdef_sz:#x}")

# ── verify string table: print first 64 bytes ─────────────────────────────────
print(f"\n[*] pair[{STR_PI}] first 64 bytes (string table verify):")
chunk = meta_data[str_off:str_off+64]
print("  hex: " + ' '.join(f'{b:02x}' for b in chunk))
print("  asc: " + ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk))

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── build typedef table ───────────────────────────────────────────────────────
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

# ── try fieldDef as 12-byte vs 16-byte entries ────────────────────────────────

for FD_SIZE, label in ((12, "12-byte (classic)"), (16, "16-byte (v31 hypothesis)")):
    n_fields = fdef_sz // FD_SIZE
    print(f"\n{'='*60}")
    print(f"[*] fieldDef as {label}  n_fields={n_fields}")

    if motor_td and motor_td['field_start'] != 0xFFFFFFFF:
        fs = motor_td['field_start']
        fc = motor_td['field_count']
        print(f"\n  CharacterMotor: field_start={fs}  field_count={fc}")
        print(f"  {'idx':<6} {'field_name':<40} {'raw_u32_0':<12} {'raw_u32_1':<12} "
              f"{'raw_u32_2':<12}" + (f" {'raw_u32_3':<12}" if FD_SIZE==16 else ""))

        for fi in range(min(20, fc)):
            abs_fi = fs + fi
            if abs_fi * FD_SIZE + FD_SIZE > fdef_sz:
                print(f"  [{abs_fi}] out of range")
                continue
            b = fdef_off + abs_fi * FD_SIZE
            if FD_SIZE == 12:
                u0, u1, u2 = struct.unpack_from("<III", meta_data, b)
                u3 = None
            else:
                u0, u1, u2, u3 = struct.unpack_from("<IIII", meta_data, b)
            try:
                fname = cstr(u0)
            except Exception:
                fname = f"<bad_str@{u0:#x}>"
            # mark sane offset (u2 for 12-byte, u3 for 16-byte)
            foff_cand = u3 if FD_SIZE == 16 else u2
            sane = "*" if 0x10 <= (foff_cand & 0x7FFFFFFF) <= 0x2000 else " "
            row = (f"  [{abs_fi}]{sane} {fname:<40} {u0:#010x}  {u1:#010x}  "
                   f"{u2:#010x}")
            if u3 is not None:
                row += f"  {u3:#010x}"
            print(row)

    # also try CIC
    if cic_td and cic_td['field_start'] != 0xFFFFFFFF:
        fs = cic_td['field_start']
        fc = cic_td['field_count']
        print(f"\n  CharacterInputController: field_start={fs:#x}  field_count={fc}")
        for fi in range(fc):
            abs_fi = fs + fi
            if abs_fi * FD_SIZE + FD_SIZE > fdef_sz:
                print(f"  [{abs_fi}] out of range")
                continue
            b = fdef_off + abs_fi * FD_SIZE
            if FD_SIZE == 12:
                u0, u1, u2 = struct.unpack_from("<III", meta_data, b)
                u3 = None
            else:
                u0, u1, u2, u3 = struct.unpack_from("<IIII", meta_data, b)
            try:
                fname = cstr(u0)
            except Exception:
                fname = f"<bad_str@{u0:#x}>"
            foff_cand = u3 if FD_SIZE == 16 else u2
            sane = "*" if 0x10 <= (foff_cand & 0x7FFFFFFF) <= 0x2000 else " "
            row = f"  [{abs_fi}]{sane} {fname:<40} u3={foff_cand:#010x}"
            print(row)

# ── raw hex of first 3 fieldDef entries ───────────────────────────────────────
print(f"\n[*] raw hex: first 3 × 16 bytes at fdef_off={fdef_off:#x}:")
for i in range(3):
    chunk = meta_data[fdef_off + i*16 : fdef_off + i*16 + 16]
    hex_s = ' '.join(f'{b:02x}' for b in chunk)
    u32s  = struct.unpack_from("<IIII", meta_data, fdef_off + i*16)
    names = []
    for u in u32s:
        try:
            names.append(repr(cstr(u)))
        except Exception:
            names.append(f"<{u:#x}>")
    print(f"  [{i}] {hex_s}  u32={[f'{u:#010x}' for u in u32s]}")
    print(f"       as_names={names}")

# ── also dump raw hex of CIC typedef to double-check FC_OFF ───────────────────
if cic_td:
    b = type_off + cic_td['typedef_idx'] * TD_SIZE
    print(f"\n[*] CIC raw typedef hex (88 bytes) at {b:#x}:")
    for row in range(0, 88, 16):
        chunk = meta_data[b+row:b+row+16]
        hex_s = ' '.join(f'{c:02x}' for c in chunk)
        u32s  = struct.unpack_from("<IIII", meta_data, b+row)
        print(f"  +{row:02x}  {hex_s}  "
              f"{[f'{u:#010x}' for u in u32s]}")

result = {"metadata_version": version, "note": "diagnostic run — see stdout"}
with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)
print(f"\n[*] written to {OUT}")