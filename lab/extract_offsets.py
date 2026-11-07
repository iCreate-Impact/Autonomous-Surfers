#!/usr/bin/env python3
"""
extract_offsets.py v2 — find _currentLaneIndex across the full class hierarchy
Handles the case where CharacterInputController.fieldCount=0 (fields on parent).

Usage:  py -3 extract_offsets.py base.apk
Output: offsets.json
"""

import sys, zipfile, struct, json

APK  = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT  = "offsets.json"

TARGET_CLASS  = "CharacterInputController"
TARGET_NS     = "SYBO.RunnerCore.Character"
TARGET_FIELD  = "_currentLaneIndex"

# ── extract from APK ──────────────────────────────────────────────────────────

print(f"[*] opening {APK}")
with zipfile.ZipFile(APK, 'r') as z:
    names    = z.namelist()
    lib_data  = z.read(next(n for n in names if n.endswith("arm64-v8a/libil2cpp.so")))
    meta_data = z.read(next(n for n in names if n.endswith("global-metadata.dat")))

print(f"[*] libil2cpp.so  : {len(lib_data):,} bytes")
print(f"[*] global-metadata: {len(meta_data):,} bytes")

# ── metadata helpers ──────────────────────────────────────────────────────────

magic, version = struct.unpack_from("<II", meta_data, 0)
assert magic == 0xFAB11BAF
print(f"[*] metadata version: {version}")

def pair(idx):
    return struct.unpack_from("<II", meta_data, 8 + idx * 8)

str_off,  _  = pair(2)
meth_off, meth_sz = pair(5)
type_off, type_sz = pair(19)
fdef_off, fdef_sz = pair(10)
foff_off, foff_sz = pair(11)

TD_SIZE = 88
MD_SIZE = 36
FD_SIZE = 12

n_types  = type_sz // TD_SIZE
n_fields = fdef_sz // FD_SIZE

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel : end].decode('utf-8', errors='replace')

def get_typedef(i):
    b = type_off + i * TD_SIZE
    name_idx, ns_idx = struct.unpack_from("<II", meta_data, b)
    field_start      = struct.unpack_from("<I",  meta_data, b + 36)[0]
    parent_idx       = struct.unpack_from("<i",  meta_data, b + 20)[0]  # signed, -1 = none
    field_count      = struct.unpack_from("<H",  meta_data, b + 72)[0]
    return {
        'name':        cstr(name_idx),
        'ns':          cstr(ns_idx),
        'field_start': field_start,
        'field_count': field_count,
        'parent_idx':  parent_idx,
        'type_idx':    i,
    }

def get_field(abs_fi):
    b = fdef_off + abs_fi * FD_SIZE
    name_idx = struct.unpack_from("<I", meta_data, b)[0]
    return cstr(name_idx)

def get_field_offset(abs_fi):
    raw = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)[0]
    return raw & 0x7FFFFFFF, bool(raw & 0x80000000)

# ── build full type table (name → index) ─────────────────────────────────────

print(f"[*] indexing {n_types} types...")
type_by_name = {}
all_types = []
for i in range(n_types):
    try:
        td = get_typedef(i)
        all_types.append(td)
        key = f"{td['ns']}.{td['name']}" if td['ns'] else td['name']
        type_by_name[key] = i
    except Exception:
        all_types.append(None)

# ── find target class ─────────────────────────────────────────────────────────

target_key = f"{TARGET_NS}.{TARGET_CLASS}"
assert target_key in type_by_name, f"{target_key} not found"
target_idx = type_by_name[target_key]
target_td  = all_types[target_idx]
print(f"[*] {target_key} at typedef index {target_idx}")
print(f"    fieldStart={target_td['field_start']}  fieldCount={target_td['field_count']}  parentIdx={target_td['parent_idx']}")

# ── dump all fields on target class (even if count=0, scan nearby) ────────────

def dump_fields(td, label):
    fc = td['field_count']
    fs = td['field_start']
    if fc == 0:
        print(f"  [{label}] no fields (count=0)")
        return
    print(f"  [{label}] {fc} field(s) starting at abs index {fs}:")
    for fi in range(fc):
        abs_fi = fs + fi
        fname  = get_field(abs_fi)
        foff, fstatic = get_field_offset(abs_fi)
        marker = " ← TARGET" if fname == TARGET_FIELD else ""
        print(f"    [{fi}] abs={abs_fi}  offset={foff:#x}  static={fstatic}  name='{fname}'{marker}")

dump_fields(target_td, TARGET_CLASS)

# ── walk parent chain ─────────────────────────────────────────────────────────

print(f"\n[*] walking parent chain of {TARGET_CLASS}:")
found_field_offset = None
found_in_class     = None
chain = [target_idx]
visited = set()
cur = target_td

while True:
    pidx = cur['parent_idx']
    # pidx is an index into the type definitions table (not the typeIndex table)
    # In metadata v31 parentIndex is a direct typedef index (signed, -1 = no parent)
    if pidx < 0 or pidx == 0xFFFFFFFF or pidx in visited:
        break
    visited.add(pidx)
    if pidx >= len(all_types) or all_types[pidx] is None:
        print(f"  parent idx {pidx} out of range or unreadable")
        break
    par = all_types[pidx]
    chain.append(pidx)
    pname = f"{par['ns']}.{par['name']}" if par['ns'] else par['name']
    print(f"  → {pname}  fieldStart={par['field_start']}  fieldCount={par['field_count']}")
    dump_fields(par, pname)

    # check for our field
    if par['field_count'] > 0:
        for fi in range(par['field_count']):
            abs_fi = par['field_start'] + fi
            fname  = get_field(abs_fi)
            if fname == TARGET_FIELD:
                foff, fstatic = get_field_offset(abs_fi)
                print(f"\n  *** FOUND '{TARGET_FIELD}' on {pname} ***")
                print(f"      offset={foff:#x}  static={fstatic}")
                found_field_offset = foff
                found_in_class = pname
                break

    if found_field_offset is not None:
        break
    cur = par

# ── also search ALL classes in the same namespace for the field ───────────────

if found_field_offset is None:
    print(f"\n[*] not found in parent chain — scanning all classes in {TARGET_NS}:")
    for td in all_types:
        if td is None or td['ns'] != TARGET_NS or td['field_count'] == 0:
            continue
        for fi in range(td['field_count']):
            abs_fi = td['field_start'] + fi
            try:
                fname = get_field(abs_fi)
            except Exception:
                continue
            if fname == TARGET_FIELD:
                foff, fstatic = get_field_offset(abs_fi)
                print(f"  *** FOUND on {td['ns']}.{td['name']} ***")
                print(f"      offset={foff:#x}  static={fstatic}")
                found_field_offset = foff
                found_in_class = f"{td['ns']}.{td['name']}"
                break
        if found_field_offset is not None:
            break

# ── if still not found, dump all fields in SYBO.RunnerCore.Character ──────────

if found_field_offset is None:
    print(f"\n[*] still not found — dumping all fields in {TARGET_NS} that contain 'lane' or 'Lane':")
    for td in all_types:
        if td is None or td['ns'] != TARGET_NS or td['field_count'] == 0:
            continue
        for fi in range(td['field_count']):
            abs_fi = td['field_start'] + fi
            try:
                fname = get_field(abs_fi)
            except Exception:
                continue
            if 'lane' in fname.lower():
                foff, fstatic = get_field_offset(abs_fi)
                print(f"  {td['name']}.{fname}  offset={foff:#x}  static={fstatic}")

    # Also dump every field on CharacterInputController's nearby typedef indices
    print(f"\n[*] typedef index neighbourhood (±5 of {target_idx}):")
    for i in range(max(0, target_idx-5), min(n_types, target_idx+6)):
        td = all_types[i]
        if td is None: continue
        print(f"  [{i}] {td['ns']}.{td['name']}  fields={td['field_count']}  parent={td['parent_idx']}")
        if td['field_count'] > 0:
            dump_fields(td, td['name'])

# ── ELF vtable scan (only if we have the field offset) ───────────────────────

vtable_rva      = None
il2cpp_class_rva = None

if found_field_offset is not None:
    print(f"\n[*] scanning libil2cpp.so for vtable of {TARGET_CLASS}...")

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

    needle = TARGET_CLASS.encode() + b'\x00'
    hits   = []
    pos = 0
    while True:
        p = lib_data.find(needle, pos)
        if p == -1: break
        rva = foff_to_rva(p)
        if rva: hits.append((p, rva))
        pos = p + 1

    print(f"[*] '{TARGET_CLASS}' string: {len(hits)} hit(s)")

    for (sfoff, srva) in hits:
        needle2 = struct.pack("<Q", srva)
        pos2 = 0
        while True:
            p2 = lib_data.find(needle2, pos2)
            if p2 == -1: break
            pos2 += 8
            class_rva  = foff_to_rva(p2)
            if class_rva is None: continue
            class_base = class_rva - 0x10   # name ptr is at Il2CppClass+0x10
            cfoff      = rva_to_foff(class_base)
            if cfoff is None or cfoff + 0x20 > len(lib_data): continue
            ns_ptr_rva, = struct.unpack_from("<Q", lib_data, cfoff + 0x18)
            ns_foff = rva_to_foff(ns_ptr_rva)
            if ns_foff is None: continue
            try:
                ns_end = lib_data.index(b'\x00', ns_foff)
                ns_str = lib_data[ns_foff:ns_end].decode('utf-8', errors='replace')
            except Exception:
                continue
            if ns_str != TARGET_NS: continue
            il2cpp_class_rva = class_base
            vtable_rva       = class_base + 0x128
            print(f"[*] Il2CppClass* RVA = {il2cpp_class_rva:#x}")
            print(f"[*] vtable RVA       = {vtable_rva:#x}")
            break
        if vtable_rva: break

    if not vtable_rva:
        print("[!] vtable not found via ELF scan (relocation-only refs) — field offset still valid")

# ── output ────────────────────────────────────────────────────────────────────

result = {
    "target_class":        TARGET_CLASS,
    "target_namespace":    TARGET_NS,
    "target_field":        TARGET_FIELD,
    "found_in_class":      found_in_class,
    "field_offset":        found_field_offset,
    "il2cpp_class_rva":    il2cpp_class_rva,
    "vtable_rva":          vtable_rva,
    "metadata_version":    version,
    "libil2cpp_size":      len(lib_data),
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] results:")
for k, v in result.items():
    print(f"    {k}: {hex(v) if isinstance(v, int) and v is not None else v}")
print(f"[*] written to {OUT}")