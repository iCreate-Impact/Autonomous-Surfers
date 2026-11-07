#!/usr/bin/env python3
"""
extract_offsets.py — pull IL2CPP field offset + vtable RVA for CharacterInputController
from a Subway Surfers base.apk (no Il2CppDumper needed).

Usage:
    py -3 extract_offsets.py base.apk

Output:
    offsets.json  — field_offset, vtable_rva, libil2cpp_size, metadata_version
"""

import sys, os, zipfile, struct, json

APK  = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT  = "offsets.json"

TARGET_CLASS = "CharacterInputController"
TARGET_NS    = "SYBO.RunnerCore.Character"
TARGET_FIELD = "_currentLaneIndex"

# ── 1. extract files from APK ─────────────────────────────────────────────────

print(f"[*] opening {APK}")
with zipfile.ZipFile(APK, 'r') as z:
    names = z.namelist()

    # libil2cpp.so
    lib_path = next(n for n in names if n.endswith("arm64-v8a/libil2cpp.so"))
    print(f"[*] extracting {lib_path}")
    lib_data = z.read(lib_path)

    # global-metadata.dat
    meta_path = next(n for n in names if n.endswith("global-metadata.dat"))
    print(f"[*] extracting {meta_path}")
    meta_data = z.read(meta_path)

print(f"[*] libil2cpp.so  : {len(lib_data):,} bytes")
print(f"[*] global-metadata: {len(meta_data):,} bytes")

# ── 2. parse global-metadata.dat ─────────────────────────────────────────────
# Header: magic(4) + version(4) + 31 pairs of (offset,size) each 8 bytes

MAGIC = 0xFAB11BAF

magic, version = struct.unpack_from("<II", meta_data, 0)
assert magic == MAGIC, f"bad metadata magic: {magic:#x}"
print(f"[*] metadata version: {version}")

def pair(idx):
    off = 8 + idx * 8
    return struct.unpack_from("<II", meta_data, off)  # (offset, size)

# pair indices (confirmed from reference):
#   2  = string table
#   5  = method definitions   (Il2CppMethodDefinition, 36 bytes each)
#   19 = type definitions     (Il2CppTypeDefinition,   88 bytes each)
#   10 = field definitions    (Il2CppFieldDefinition,  12 bytes each — nameIndex+typeIndex+token)
#   11 = field offsets table  (uint32 per field)

str_off,   str_sz   = pair(2)
meth_off,  meth_sz  = pair(5)
type_off,  type_sz  = pair(19)
fdef_off,  fdef_sz  = pair(10)
foff_off,  foff_sz  = pair(11)

TD_SIZE   = 88
MD_SIZE   = 36
FD_SIZE   = 12

n_types   = type_sz  // TD_SIZE
n_methods = meth_sz  // MD_SIZE
n_fields  = fdef_sz  // FD_SIZE

print(f"[*] types: {n_types}  methods: {n_methods}  fields: {n_fields}")

def cstr(offset):
    end = meta_data.index(b'\x00', str_off + offset)
    return meta_data[str_off + offset : end].decode('utf-8', errors='replace')

# ── 3. find CharacterInputController typedef ──────────────────────────────────

# Il2CppTypeDefinition (88 bytes):
#   +0   nameIndex       uint32
#   +4   namespaceIndex  uint32
#   +8   customAttributeIndex int32
#   +12  byvalTypeIndex  int32
#   +16  declaringTypeIndex int32
#   +20  parentIndex     int32
#   +24  elementTypeIndex int32
#   +28  genericContainerIndex int32
#   +32  flags           uint32
#   +36  fieldStart      uint32
#   +40  methodStart     uint32  ← NOT what we want; that changed
#   +44  eventStart      uint32
#   +48  propertyStart   uint32
#   +52  nestedTypesStart uint32
#   +56  interfacesStart uint32
#   +60  vtableStart     uint32
#   +64  interfaceOffsetsStart uint32
#   +68  method_count    uint16
#   +70  property_count  uint16
#   +72  field_count     uint16
#   +74  event_count     uint16
#   +76  nested_type_count uint16
#   +78  vtable_count    uint16  ← vtable slot count
#   +80  interfaces_count uint16
#   +82  interface_offsets_count uint16
#   +84  bitfield        uint8
#   +85  token           uint32 (may be at +84 depending on exact version)

# We'll be loose about the exact layout and confirm by name match.

target_type_idx = None
for i in range(n_types):
    base = type_off + i * TD_SIZE
    name_idx, ns_idx = struct.unpack_from("<II", meta_data, base)
    try:
        name = cstr(name_idx)
        ns   = cstr(ns_idx)
    except Exception:
        continue
    if name == TARGET_CLASS and ns == TARGET_NS:
        target_type_idx = i
        print(f"[*] found {TARGET_NS}.{TARGET_CLASS} at typedef index {i}")
        break

assert target_type_idx is not None, f"class {TARGET_CLASS} not found in metadata"

td_base     = type_off + target_type_idx * TD_SIZE
field_start = struct.unpack_from("<I", meta_data, td_base + 36)[0]
field_count = struct.unpack_from("<H", meta_data, td_base + 72)[0]

print(f"[*] fieldStart={field_start}  fieldCount={field_count}")

# ── 4. find _currentLaneIndex field + its offset ──────────────────────────────

# Il2CppFieldDefinition (12 bytes): nameIndex(4) + typeIndex(4) + token(4)
# The fieldOffsets table is a flat array of uint32, indexed by absolute field index.

target_field_idx = None
for fi in range(field_count):
    abs_fi  = field_start + fi
    fd_base = fdef_off + abs_fi * FD_SIZE
    fname_idx = struct.unpack_from("<I", meta_data, fd_base)[0]
    try:
        fname = cstr(fname_idx)
    except Exception:
        continue
    if fname == TARGET_FIELD:
        target_field_idx = abs_fi
        print(f"[*] found field '{TARGET_FIELD}' at absolute field index {abs_fi}")
        break

assert target_field_idx is not None, f"field {TARGET_FIELD} not found"

# fieldOffsets table: uint32 per entry, indexed by absolute field index
field_offset_value = struct.unpack_from("<I", meta_data, foff_off + target_field_idx * 4)[0]

# IL2CPP value-type fields stored inline have their offset biased by 0x10 (boxing header).
# For a plain int field on a MonoBehaviour, offset is direct. Flag bit 0x80000000 = static.
is_static = bool(field_offset_value & 0x80000000)
raw_offset = field_offset_value & 0x7FFFFFFF
print(f"[*] _currentLaneIndex: raw_offset={raw_offset:#x}  static={is_static}")

# ── 5. find CharacterInputController vtable RVA in libil2cpp.so ───────────────
# The vtable for a class is in the .data/.bss section of libil2cpp.so.
# Il2CppClass* has a vtable at a known layout. We find it by scanning for the
# type's Il2CppClass* via the metadata token or by pattern-matching the ELF.
#
# Simpler approach that works: scan libil2cpp.so for the UTF-8 string
# "CharacterInputController\0" then find the Il2CppClass* that references
# that string — it will be in the .rodata or .data section.
# The vtable pointer is at Il2CppClass+0x128 (Unity 2021 / metadata v31).

print(f"[*] scanning libil2cpp.so for vtable RVA...")

target_bytes = TARGET_CLASS.encode() + b'\x00'
positions = []
start = 0
while True:
    pos = lib_data.find(target_bytes, start)
    if pos == -1:
        break
    positions.append(pos)
    start = pos + 1

print(f"[*] '{TARGET_CLASS}' string found at {len(positions)} location(s) in libil2cpp.so")

# Parse ELF to get load address of each section so we can convert file offsets → RVAs
# ELF64 header: magic(4)+class(1)+data(1)+version(1)+osabi(1)+pad(8)+type(2)+machine(2)+
#               version2(4)+entry(8)+phoff(8)+shoff(8)+flags(4)+ehsize(2)+phentsize(2)+
#               phnum(2)+shentsize(2)+shnum(2)+shstrndx(2)

assert lib_data[:4] == b'\x7fELF', "not an ELF"
e_phoff, = struct.unpack_from("<Q", lib_data, 32)
e_phnum, = struct.unpack_from("<H", lib_data, 56)
PH_SIZE = 56  # PT_PHDR entry size for ELF64

# Build list of LOAD segments: (p_vaddr, p_offset, p_filesz)
load_segs = []
for i in range(e_phnum):
    ph = e_phoff + i * PH_SIZE
    p_type,  = struct.unpack_from("<I", lib_data, ph)
    if p_type != 1:  # PT_LOAD
        continue
    p_offset, = struct.unpack_from("<Q", lib_data, ph + 8)
    p_vaddr,  = struct.unpack_from("<Q", lib_data, ph + 16)
    p_filesz, = struct.unpack_from("<Q", lib_data, ph + 32)
    load_segs.append((p_vaddr, p_offset, p_filesz))

def file_offset_to_rva(foff):
    for (vaddr, seg_off, filesz) in load_segs:
        if seg_off <= foff < seg_off + filesz:
            return vaddr + (foff - seg_off)
    return None

def rva_to_file_offset(rva):
    for (vaddr, seg_off, filesz) in load_segs:
        if vaddr <= rva < vaddr + filesz:
            return seg_off + (rva - vaddr)
    return None

# For each string hit, find 8-byte pointers to it in the library (Il2CppClass.name ptr)
string_rvas = [file_offset_to_rva(p) for p in positions if file_offset_to_rva(p)]
print(f"[*] string RVAs: {[hex(r) for r in string_rvas]}")

# Scan .rodata / .data for pointers to these RVAs
# In a PIC shared lib, pointers are stored as absolute VAs at load time (via RELA).
# But in the file, they appear as RVAs (or 0 with a relocation). 
# More reliable: scan for the string RVA as a little-endian uint64 in the file.

candidate_class_ptrs = []
for srva in string_rvas:
    needle = struct.pack("<Q", srva)
    pos2 = 0
    while True:
        pos2 = lib_data.find(needle, pos2)
        if pos2 == -1:
            break
        # This file offset holds a pointer to our string — likely Il2CppClass.name
        ptr_rva = file_offset_to_rva(pos2)
        if ptr_rva:
            candidate_class_ptrs.append((pos2, ptr_rva))
        pos2 += 8

print(f"[*] Il2CppClass* candidates (name ptr hits): {len(candidate_class_ptrs)}")

# Il2CppClass layout (Unity 2021, metadata v31, ARM64):
# +0x00  image*
# +0x08  gc_desc*
# +0x10  name*          ← we matched here
# +0x18  namespaze*
# +0x20  byval_arg*
# +0x28  this_arg*
# +0x30  element_class*
# +0x38  castClass*
# +0x40  declaringType*
# +0x48  parent*
# +0x50  generic_class*
# +0x58  typeMetadataHandle*
# +0x60  interopData*
# +0x68  klass*         (self-referential)
# +0x70  fields*
# +0x78  events*
# +0x80  properties*
# +0x88  methods**
# +0x90  nestedTypes**
# +0x98  implementedInterfaces**
# +0xA0  interfaceOffsets*
# +0xA8  static_fields*
# +0xB0  rgctx_data*
# +0xB8  typeHierarchy**
# +0xC0  unity_user_data*
# +0xC8  initializationExceptionGCHandle uint32
# +0xCC  cctor_started uint32
# +0xD0  cctor_finished uint32 (pad to 0xD8)
# +0xD8  genericRecursionDepth size_t
# ... flags, token, etc.
# +0x128 vtable[0]      ← first vtable slot (VirtualInvokeData: method* + method_ptr*)

VTABLE_OFFSET_IN_CLASS = 0x128

vtable_rva = None
il2cpp_class_rva = None

for (name_foff, name_ptr_rva) in candidate_class_ptrs:
    # name ptr is at Il2CppClass+0x10, so class base RVA = name_ptr_rva - 0x10
    class_rva  = name_ptr_rva - 0x10
    class_foff = rva_to_file_offset(class_rva)
    if class_foff is None or class_foff + 0x20 > len(lib_data):
        continue

    # verify by checking namespaze pointer (at +0x18) points to TARGET_NS string
    ns_ptr_rva, = struct.unpack_from("<Q", lib_data, class_foff + 0x18)
    ns_foff = rva_to_file_offset(ns_ptr_rva)
    if ns_foff is None:
        continue
    try:
        ns_end = lib_data.index(b'\x00', ns_foff)
        ns_str = lib_data[ns_foff:ns_end].decode('utf-8', errors='replace')
    except Exception:
        continue

    if ns_str != TARGET_NS:
        continue

    print(f"[*] confirmed Il2CppClass* at RVA {class_rva:#x}  ns='{ns_str}'")
    il2cpp_class_rva = class_rva

    vtable_rva = class_rva + VTABLE_OFFSET_IN_CLASS
    print(f"[*] vtable RVA = {vtable_rva:#x}")
    break

if vtable_rva is None:
    print("[!] vtable not found via class scan — may need RELA relocation resolution")
    print("[!] outputting what we have; vtable_rva will be null in offsets.json")

# ── 6. write offsets.json ─────────────────────────────────────────────────────

result = {
    "target_class":     TARGET_CLASS,
    "target_namespace": TARGET_NS,
    "target_field":     TARGET_FIELD,
    "field_offset":     raw_offset,
    "field_is_static":  is_static,
    "il2cpp_class_rva": il2cpp_class_rva,
    "vtable_rva":       vtable_rva,
    "vtable_offset_in_class": VTABLE_OFFSET_IN_CLASS,
    "metadata_version": version,
    "libil2cpp_size":   len(lib_data),
}

with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n[*] done. results:")
for k, v in result.items():
    print(f"    {k}: {hex(v) if isinstance(v, int) else v}")
print(f"\n[*] written to {OUT}")