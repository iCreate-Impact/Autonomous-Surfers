#!/usr/bin/env python3
"""
extract_offsets.py v10

Hardcoded pair indices confirmed from pair table dump:
  pair[ 2]: off=0x0cd54c  sz=0x257150  first_byte=0x41 → name string table
  pair[10]: off=0x928550  sz=0x157350  /12=117148       → Il2CppFieldDefinition[]
  pair[19]: off=0xc86d68  sz=0x1b6218  /88=20393        → Il2CppTypeDefinition[]

String table starts at a non-null byte — cstr(0) gives us whatever the first
name is. We find the right string offset by locating a known class name.

fieldDef entry size: test both 12 and 16 bytes.
Field offset source: either baked into fdef (16-byte) or pair[11] (12-byte legacy).

pair[11]: off=0xa7f8a0  sz=0x1008a8  /4=262698  /12=87566

Usage:  py -3 extract_offsets.py base.apk
Output: offsets.json
"""

import sys, zipfile, struct, json

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "offsets.json"

TARGET_FIELD  = "_currentLaneIndex"
LANE_KEYWORDS = ["lane", "Lane"]

# ── confirmed pair indices ────────────────────────────────────────────────────
STR_PI  = 2    # name string table  (first_byte=0x41, sz=0x257150)
TYPE_PI = 19   # Il2CppTypeDefinition[]  (sz/88=20393)
FDEF_PI = 10   # Il2CppFieldDefinition[] (sz/12=117148 or sz/16=87861)
FOFF_PI = 11   # candidate field offset table (sz/4=262698, /12=87566)

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

str_off,  str_sz  = pair(STR_PI)
type_off, type_sz = pair(TYPE_PI)
fdef_off, fdef_sz = pair(FDEF_PI)
foff_off, foff_sz = pair(FOFF_PI)

n_types = type_sz // TD_SIZE
print(f"[*] n_types={n_types}")
print(f"[*] str_off={str_off:#x}  type_off={type_off:#x}  "
      f"fdef_off={fdef_off:#x}  foff_off={foff_off:#x}")

# ── string table: print first 32 bytes to confirm ────────────────────────────
print(f"\n[*] pair[{STR_PI}] first 32 bytes:")
chunk = meta_data[str_off:str_off+32]
print("  hex: " + ' '.join(f'{b:02x}' for b in chunk))
print("  asc: " + ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk))

# cstr reads from str_off + rel, stopping at null
def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── verify typedef table: print first 5 type names ───────────────────────────
print(f"\n[*] first 5 typedef names (verify string table):")
for i in range(5):
    b = type_off + i * TD_SIZE
    try:
        ni, nsi = struct.unpack_from("<II", meta_data, b)
        print(f"  [{i}] nameIdx={ni:#x} → '{cstr(ni)}'  ns='{cstr(nsi)}'")
    except Exception as e:
        print(f"  [{i}] error: {e}")

# ── build typedef table ───────────────────────────────────────────────────────
print(f"\n[*] building typedef table...")
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

cic_td = next((td for td in all_types
               if td and td['name'] == 'CharacterInputController'
               and td['ns'] == 'SYBO.RunnerCore.Character'), None)
motor_td = next((td for td in all_types
                 if td and td['name'] == 'CharacterMotor'
                 and td['ns'] == 'SYBO.RunnerCore.Character'), None)

print(f"[*] CIC:   {cic_td}")
print(f"[*] Motor: field_start={motor_td['field_start'] if motor_td else 'NOT FOUND'}  "
      f"field_count={motor_td['field_count'] if motor_td else '?'}")

# ── fieldDef entry size probe ─────────────────────────────────────────────────
# Try 12 and 16 byte entries. For each, dump CharacterMotor's first 15 fields.
# The correct size gives real names in column 0 and sane offsets in last column.

print(f"\n[*] fdef_sz={fdef_sz:#x}")
for FD_SIZE in (12, 16):
    n_fields = fdef_sz // FD_SIZE
    print(f"\n{'='*70}")
    print(f"[*] fieldDef entry_size={FD_SIZE}  n_fields={n_fields}")

    # CharacterMotor first 15 fields
    if motor_td and motor_td['field_start'] != 0xFFFFFFFF:
        fs = motor_td['field_start']
        fc = motor_td['field_count']
        print(f"\n  CharacterMotor (fs={fs}, fc={fc}) first 15 fields:")
        for fi in range(min(15, fc)):
            abs_fi = fs + fi
            byte_off = abs_fi * FD_SIZE
            if byte_off + FD_SIZE > fdef_sz:
                print(f"    [{abs_fi}] out of range")
                continue
            b = fdef_off + byte_off
            words = struct.unpack_from(f"<{'I'*(FD_SIZE//4)}", meta_data, b)
            try:
                fname = cstr(words[0])
            except Exception:
                fname = f"<bad@{words[0]:#x}>"
            # last word as potential offset
            last = words[-1]
            inst  = last & 0x7FFFFFFF
            stat  = bool(last & 0x80000000)
            sane  = "*" if 0x10 <= inst <= 0x2000 and not stat else " "
            wstrs = "  ".join(f"{w:#010x}" for w in words)
            print(f"    [{abs_fi}]{sane} {fname:<35} | {wstrs}")

    # CIC fields
    if cic_td and cic_td['field_start'] != 0xFFFFFFFF:
        fs = cic_td['field_start']
        fc = cic_td['field_count']
        print(f"\n  CharacterInputController (fs={fs:#x}, fc={fc}) fields:")
        for fi in range(fc):
            abs_fi = fs + fi
            byte_off = abs_fi * FD_SIZE
            if byte_off + FD_SIZE > fdef_sz:
                print(f"    [{abs_fi}] out of range")
                continue
            b = fdef_off + byte_off
            words = struct.unpack_from(f"<{'I'*(FD_SIZE//4)}", meta_data, b)
            try:
                fname = cstr(words[0])
            except Exception:
                fname = f"<bad@{words[0]:#x}>"
            last = words[-1]
            inst = last & 0x7FFFFFFF
            stat = bool(last & 0x80000000)
            sane = "*" if 0x10 <= inst <= 0x2000 and not stat else " "
            wstrs = "  ".join(f"{w:#010x}" for w in words)
            print(f"    [{abs_fi}]{sane} {fname:<35} | {wstrs}")

    # Also try pair[11] as the offset source (12-byte fdef, separate foff)
    if FD_SIZE == 12:
        print(f"\n  Pair[11] as foff (sz={foff_sz:#x}, /4={foff_sz//4}):")
        print(f"  CharacterMotor first 15 with pair[11] offsets:")
        if motor_td and motor_td['field_start'] != 0xFFFFFFFF:
            fs = motor_td['field_start']
            for fi in range(min(15, motor_td['field_count'])):
                abs_fi = fs + fi
                b = fdef_off + abs_fi * FD_SIZE
                try:
                    ni, = struct.unpack_from("<I", meta_data, b)
                    fname = cstr(ni)
                except Exception:
                    fname = f"<bad>"
                # pair[11] as foff
                if abs_fi * 4 + 4 <= foff_sz:
                    raw, = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
                    inst = raw & 0x7FFFFFFF
                    stat = bool(raw & 0x80000000)
                    sane = "*" if 0x10 <= inst <= 0x2000 and not stat else " "
                    print(f"    [{abs_fi}]{sane} {fname:<35} | p11={raw:#010x}  "
                          f"inst={inst:#x}  static={stat}")
                else:
                    print(f"    [{abs_fi}]  {fname:<35} | p11=OOB")

# ── raw hex: first 3 fdef entries × 16 bytes ─────────────────────────────────
print(f"\n[*] raw fdef first 3 entries × 16 bytes at {fdef_off:#x}:")
for i in range(3):
    b = fdef_off + i * 16
    chunk = meta_data[b:b+16]
    hexs  = ' '.join(f'{x:02x}' for x in chunk)
    words = struct.unpack_from("<IIII", meta_data, b)
    names = []
    for w in words:
        try:    names.append(repr(cstr(w)))
        except: names.append(f"<{w:#x}>")
    print(f"  [{i}] {hexs}")
    print(f"       {[f'{w:#010x}' for w in words]}")
    print(f"       as_str: {names}")

result = {"metadata_version": version, "note": "v10 diagnostic"}
with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)
print(f"\n[*] written to {OUT}")