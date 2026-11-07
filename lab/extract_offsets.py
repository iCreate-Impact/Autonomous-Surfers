#!/usr/bin/env python3
"""
extract_offsets.py v6

Fixes confirmed from hex dump:
  - FC_OFF = 64  (uint16 at +0x40, not +0x44)
  - FS_OFF = 32  (confirmed correct)
  - parentIdx in v31 is a packed type token, not a raw typeIndex
    upper 13 bits = assembly index, lower 19 bits = local type index within assembly
    We decode it via the assembly/image tables instead of pair[22].

Changes:
  - correct FC_OFF
  - parent resolution via image table (pair[17]=imageDefinitions, pair[0]=assemblies)
  - dumps the 3 CIC fields explicitly
  - sane offset range widened to 0x10..0x2000 (some Unity objects are bigger)
  - EmojiList diagnosis: reports its field range so we can see the overlap

Usage:  py -3 extract_offsets.py base.apk
Output: offsets.json
"""

import sys, zipfile, struct, json

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "offsets.json"

TARGET_FIELD  = "_currentLaneIndex"
LANE_KEYWORDS = ["lane", "Lane"]

# ── confirmed layout constants ────────────────────────────────────────────────
TD_SIZE    = 88
FS_OFF     = 32   # field_start (uint32) within Il2CppTypeDefinition
FC_OFF     = 64   # field_count (uint16) — FIXED from hex dump (+0x40)
PARENT_OFF = 20   # parentIdx  (int32)  — packed token in v31

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
print(f"[*] layout: TD_SIZE={TD_SIZE}  FS_OFF={FS_OFF}  FC_OFF={FC_OFF}  PARENT_OFF={PARENT_OFF}")

def cstr(rel):
    end = meta_data.index(b'\x00', str_off + rel)
    return meta_data[str_off + rel:end].decode('utf-8', errors='replace')

# ── image/assembly table for parent token resolution ─────────────────────────
# Il2CppImageDefinition (v27+): firstTypeIndex(uint32) + typeCount(uint32) + ...
# pair[17] = imageDefinitions, each entry is 20 bytes in v27, possibly 24 in v31
# We probe the entry size by checking that firstTypeIndex[0]=0 and
# firstTypeIndex[0]+typeCount[0] <= n_types for a few images.

IMG_ENTRY_SIZES = (20, 24, 28)
img_off, img_sz = pair(17)
img_entry_size  = None
n_images        = 0

for es in IMG_ENTRY_SIZES:
    n = img_sz // es
    if n == 0:
        continue
    # first image usually starts at typedef 0
    fi0, = struct.unpack_from("<I", meta_data, img_off)
    tc0, = struct.unpack_from("<I", meta_data, img_off + 4)
    if fi0 == 0 and 0 < tc0 <= n_types:
        img_entry_size = es
        n_images = n
        print(f"[*] image table: pair[17]  entry_size={es}  n_images={n}")
        break

# build image → (firstTypeIndex, typeCount) table
images = []
if img_entry_size:
    for i in range(n_images):
        b = img_off + i * img_entry_size
        fi, = struct.unpack_from("<I", meta_data, b)
        tc, = struct.unpack_from("<I", meta_data, b + 4)
        images.append((fi, tc))

def decode_parent_token(token):
    """
    v31 parentIdx encoding: packed type token.
    upper 13 bits = image/assembly index, lower 19 bits = local type index.
    Returns typedef index or None.
    """
    if token < 0 or token == 0x7FFFFFFF:
        return None
    img_idx   = (token >> 19) & 0x1FFF
    local_idx =  token        & 0x7FFFF
    if img_idx < len(images):
        first, count = images[img_idx]
        global_idx = first + local_idx
        if global_idx < n_types:
            return global_idx
    # fallback: try as raw typedef index
    if token < n_types:
        return token
    return None

# ── build typedef table ───────────────────────────────────────────────────────

print(f"[*] building typedef table...")
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

top5 = sorted([td for td in all_types if td],
              key=lambda t: t['field_count'], reverse=True)[:5]
print(f"[*] top 5 classes by field_count:")
for td in top5:
    ns_name = f"{td['ns']}.{td['name']}" if td['ns'] else td['name']
    print(f"    {ns_name}  field_count={td['field_count']}  "
          f"field_start={td['field_start']}  "
          f"range=[{td['field_start']}..{td['field_start']+td['field_count']-1}]")

# ── EmojiList diagnosis ───────────────────────────────────────────────────────
emoji = next((td for td in all_types if td and td['name'] == 'EmojiList'), None)
if emoji:
    print(f"\n[*] EmojiList: field_start={emoji['field_start']}  "
          f"field_count={emoji['field_count']}  "
          f"range=[{emoji['field_start']}..{emoji['field_start']+emoji['field_count']-1}]")
    print(f"    abs_fi 735..3047 fall inside this range: "
          f"{emoji['field_start']} <= 735 and 3047 <= {emoji['field_start']+emoji['field_count']-1}")

# ── dump CharacterInputController fields explicitly ───────────────────────────

print(f"\n[*] CharacterInputController explicit field dump:")
cic_td = next((td for td in all_types
               if td and td['name'] == 'CharacterInputController'
               and td['ns'] == 'SYBO.RunnerCore.Character'), None)

if not cic_td:
    print("  NOT FOUND")
else:
    print(f"  typedef_idx={cic_td['typedef_idx']}  "
          f"field_start={cic_td['field_start']}  "
          f"field_count={cic_td['field_count']}  "
          f"parent_tidx={cic_td['parent_tidx']}")
    # decode parent
    parent_resolved = decode_parent_token(cic_td['parent_tidx'])
    if parent_resolved is not None and all_types[parent_resolved]:
        pt = all_types[parent_resolved]
        print(f"  parent resolved → [{parent_resolved}] "
              f"{pt['ns']}.{pt['name']}  "
              f"field_count={pt['field_count']}")
    else:
        print(f"  parent token {cic_td['parent_tidx']} → unresolvable")

    for fi in range(cic_td['field_count']):
        abs_fi = cic_td['field_start'] + fi
        b = fdef_off + abs_fi * FD_SIZE
        try:
            name_idx, = struct.unpack_from("<I", meta_data, b)
            fname     = cstr(name_idx)
            raw,      = struct.unpack_from("<I", meta_data, foff_off + abs_fi * 4)
            foff      = raw & 0x7FFFFFFF
            static    = bool(raw & 0x80000000)
            marker    = " ← TARGET" if fname == TARGET_FIELD else ""
            print(f"  [{abs_fi}] '{fname}'  offset={foff:#x}  static={static}{marker}")
        except Exception as ex:
            print(f"  [{abs_fi}] error: {ex}")

# ── parent chain walk ─────────────────────────────────────────────────────────

print(f"\n[*] full parent chain of CharacterInputController:")
if cic_td:
    visited = set()
    cur     = cic_td
    depth   = 0
    while cur:
        if cur['typedef_idx'] in visited:
            print(f"  [depth {depth}] circular, stopping")
            break
        visited.add(cur['typedef_idx'])
        ns_name = f"{cur['ns']}.{cur['name']}" if cur['ns'] else cur['name']
        print(f"  [depth {depth}] [{cur['typedef_idx']}] {ns_name}  "
              f"fields={cur['field_count']}  field_start={cur['field_start']}")

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

        parent_resolved = decode_parent_token(cur['parent_tidx'])
        if parent_resolved is None:
            print(f"  → no parent (token={cur['parent_tidx']}), stopping")
            break
        next_td = all_types[parent_resolved] if parent_resolved < len(all_types) else None
        if next_td is None:
            print(f"  → parent typedef {parent_resolved} unreadable, stopping")
            break
        cur   = next_td
        depth += 1
        if depth > 25:
            print("  [depth limit]")
            break

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
    sane_s = " [sane]" if e['sane'] else ""
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
        [e for e in lane_fields if e['sane'] and e['owner'] != '<unknown>' and e['field_name'] in priority],
        [e for e in lane_fields if e['sane'] and e['owner'] != '<unknown>'],
        [e for e in lane_fields if e['sane']],
    ):
        if pool:
            best = pool[0]
            break

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
    print(f"\n[*] '{class_simple}' string: {len(hits)} hit(s) in libil2cpp.so")

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
            vtable_rva       = class_base + 0x128
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
    "found_in_class":   best['owner']      if best else None,
    "field_name_used":  best['field_name'] if best else None,
    "field_offset":     best['offset']     if best else None,
    "il2cpp_class_rva": il2cpp_class_rva,
    "vtable_rva":       vtable_rva,
    "metadata_version": version,
    "libil2cpp_size":   len(lib_data),
    "field_layout":     {"TD_SIZE": TD_SIZE, "FS_OFF": FS_OFF, "FC_OFF": FC_OFF, "PARENT_OFF": PARENT_OFF},
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