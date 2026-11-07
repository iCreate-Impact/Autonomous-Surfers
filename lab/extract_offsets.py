#!/usr/bin/env python3
"""
extract_offsets.py v11

New since v10:
  · Brute-force scan of ALL 117,148 field defs for "lane" (case-insensitive)
  · Reverse abs_fi → typedef map so each hit knows its owning class
  · CharacterMotor: dump all 136 fields (not just first 15)
  · CIC parent chain: probe pair[20] Il2CppType[] at entry_sz 8 and 12
  · ELF .dynsym / .symtab: il2cpp_field_* exports + any g_FieldOffset data symbols
  · Fallback: if no lane hit, dump SYBO-namespace fields containing
    "current" / "index" / "col" / "track" / "dir"  (capped at 60 lines)

Confirmed from v10:
  pair[ 2] = string table        str_off=0x0cd54c
  pair[10] = Il2CppFieldDef[]    fdef_off=0x928550  entry_size=12  n=117148
  pair[11] = candidate foff      foff_off=0xa7f8a0
  pair[19] = Il2CppTypeDef[]     type_off=0xc86d68  TD_SIZE=88  n=20393
  pair[20] = Il2CppType[]        probed below (entry_sz 8 or 12)
  FS_OFF=32 · FC_OFF=64 · PARENT_OFF=20  — correct (CharacterMotor verifies)
  12-byte fieldDef layout: nameIdx(4) | typeRef_or_caIdx(4) | typeIdx_or_token(4)
  CIC: field_start=0xFFFFFFFF sentinel · field_count=3 · parent_tidx=23106 TypeIndex
  Field offsets are NOT in v31 metadata.
  At boot-time use: il2cpp_class_get_fields() + il2cpp_field_get_offset()

Usage: py -3 extract_offsets.py base.apk
Out:   lane_hits.json
"""

import sys, zipfile, struct, json

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "lane_hits.json"

LANE_KW     = ["lane"]
FALLBACK_KW = ["current", "index", "col", "track", "dir"]

STR_PI  = 2;  FDEF_PI = 10; FOFF_PI = 11
TYPE_PI = 19; ITYPE_PI = 20

TD_SIZE = 88; FS_OFF = 32; FC_OFF = 64; PARENT_OFF = 20
FD_SIZE = 12; SENTINEL = 0xFFFF_FFFF

IL2CPP_CLASS = 0x11; IL2CPP_VT = 0x12

# ── load ──────────────────────────────────────────────────────────────────────
print(f"[*] opening {APK}")
with zipfile.ZipFile(APK) as z:
    ns   = z.namelist()
    lib  = z.read(next(n for n in ns if n.endswith("arm64-v8a/libil2cpp.so")))
    meta = z.read(next(n for n in ns if n.endswith("global-metadata.dat")))

magic, ver = struct.unpack_from("<II", meta, 0)
assert magic == 0xFAB11BAF, f"bad magic {magic:#010x}"
print(f"[*] metadata v{ver}  lib={len(lib):,}B  meta={len(meta):,}B")

def _pair(i): return struct.unpack_from("<II", meta, 8 + i * 8)

str_off,   str_sz   = _pair(STR_PI)
type_off,  type_sz  = _pair(TYPE_PI)
fdef_off,  fdef_sz  = _pair(FDEF_PI)
foff_off,  foff_sz  = _pair(FOFF_PI)
itype_off, itype_sz = _pair(ITYPE_PI)

n_types = type_sz  // TD_SIZE
n_fdefs = fdef_sz  // FD_SIZE
print(f"[*] n_types={n_types}  n_fdefs={n_fdefs}")
print(f"[*] pair[20] off={itype_off:#x}  sz={itype_sz:#x}  "
      f"/8={itype_sz//8}  /12={itype_sz//12}")

# string table cached slice — index() on a slice is much faster than on full meta
_STR = meta[str_off:str_off + str_sz]

def cstr(r):
    if r >= str_sz:
        return f"<OOB:{r:#x}>"
    try:
        e = _STR.index(b'\x00', r)
        return _STR[r:e].decode('utf-8', 'replace')
    except ValueError:
        return _STR[r:].decode('utf-8', 'replace')

# ── typedef table ─────────────────────────────────────────────────────────────
print("[*] building typedef table...")
tdefs = []
for i in range(n_types):
    b = type_off + i * TD_SIZE
    try:
        ni, nsi = struct.unpack_from("<II", meta, b)
        fs,     = struct.unpack_from("<I",  meta, b + FS_OFF)
        fc,     = struct.unpack_from("<H",  meta, b + FC_OFF)
        pt,     = struct.unpack_from("<i",  meta, b + PARENT_OFF)
        tdefs.append({'i': i, 'name': cstr(ni), 'ns': cstr(nsi),
                      'fs': fs, 'fc': fc, 'pt': pt})
    except Exception:
        tdefs.append(None)

def _find(name, ns):
    return next((t for t in tdefs if t and t['name'] == name and t['ns'] == ns), None)

cic   = _find('CharacterInputController', 'SYBO.RunnerCore.Character')
motor = _find('CharacterMotor',           'SYBO.RunnerCore.Character')
print(f"[*] CIC   : {cic}")
print(f"[*] Motor : {motor}")

# ── CIC parent chain via pair[20] ─────────────────────────────────────────────
# Il2CppType: data(uint32) | attrs(uint16) | type_enum(uint8) | bitfield(uint8)
# If type_enum in {0x11 CLASS, 0x12 VALUETYPE}: data = TypeDefinitionIndex
print(f"\n[*] CIC parent chain (TypeIndex={cic['pt'] if cic else '?'}):")
if cic:
    ptidx = cic['pt']
    for esz in (8, 12):
        n_it = itype_sz // esz
        sys.stdout.write(f"  esz={esz}  n_entries={n_it}  ")
        if not (0 <= ptidx < n_it):
            print("OOB"); continue
        b = itype_off + ptidx * esz
        data, attrs, te = struct.unpack_from("<IHB", meta, b)
        sys.stdout.write(f"data={data:#x}  attrs={attrs:#x}  te={te:#04x}  ")
        if te in (IL2CPP_CLASS, IL2CPP_VT):
            if 0 <= data < len(tdefs) and tdefs[data]:
                p = tdefs[data]
                print(f"→ '{p['ns']}.{p['name']}'  "
                      f"fs={p['fs']}  fc={p['fc']}  typedef_idx={p['i']}")
            else:
                print(f"→ typedef_idx={data} OOB or null")
        else:
            print("→ not CLASS/VALUETYPE — probably wrong esz")

# ── reverse map: abs_fi → typedef ─────────────────────────────────────────────
print("\n[*] building reverse field → typedef map...")
f2t = {}
for td in tdefs:
    if not td or td['fs'] == SENTINEL or td['fc'] == 0:
        continue
    for i in range(td['fc']):
        fi = td['fs'] + i
        if fi < n_fdefs:
            f2t[fi] = td
print(f"[*] mapped {len(f2t)} entries  "
      f"({n_fdefs - len(f2t)} fields belong to sentinel-start classes)")

def _p11(abs_fi):
    off = abs_fi * 4
    if off + 4 <= foff_sz:
        return struct.unpack_from("<I", meta, foff_off + off)[0]
    return None

# ── brute-force lane scan ─────────────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"[*] BRUTE FORCE: {n_fdefs} field defs — keywords={LANE_KW!r} (case-insensitive)")

lane_hits = []
for abs_fi in range(n_fdefs):
    b = fdef_off + abs_fi * FD_SIZE
    if b + FD_SIZE > len(meta):
        print(f"  [!] OOB at abs_fi={abs_fi}"); break
    ni, w1, w2 = struct.unpack_from("<III", meta, b)
    if ni >= str_sz:
        continue
    nm = cstr(ni)
    if not any(k in nm.lower() for k in LANE_KW):
        continue

    td  = f2t.get(abs_fi)
    p11 = _p11(abs_fi)
    h   = dict(abs_fi=abs_fi, name=nm,
               cls=td['name'] if td else None,
               ns =td['ns']   if td else None,
               ti =td['i']    if td else -1,
               w1=w1, w2=w2, p11=p11)
    lane_hits.append(h)

    cln = f"{td['ns']}.{td['name']}" if td else "(no owner — class has sentinel field_start)"
    print(f"  [{abs_fi:6d}] '{nm}'")
    print(f"           {cln}  typedef_idx={h['ti']}")
    print(f"           w1={w1:#010x}  w2={w2:#010x}", end="")
    if p11 is not None:
        print(f"  p11={p11:#010x}", end="")
    print()

if not lane_hits:
    print("  *** no 'lane' hits — running fallback scan for SYBO-namespace fields ***")
    printed = 0
    for abs_fi in range(n_fdefs):
        if printed >= 60:
            print("  ... (capped at 60 lines)"); break
        b = fdef_off + abs_fi * FD_SIZE
        if b + FD_SIZE > len(meta): break
        ni, w1, w2 = struct.unpack_from("<III", meta, b)
        if ni >= str_sz: continue
        nm = cstr(ni)
        if not any(k in nm.lower() for k in FALLBACK_KW): continue
        td = f2t.get(abs_fi)
        if not td: continue
        ns = td['ns']
        if 'SYBO' not in ns and 'Runner' not in ns: continue
        print(f"  [{abs_fi:6d}] {nm:<42} {ns}.{td['name']}"
              f"  w2={w2:#010x}")
        printed += 1

# ── CharacterMotor: ALL fields ────────────────────────────────────────────────
print(f"\n{'='*70}")
if motor and motor['fs'] != SENTINEL:
    fs, fc = motor['fs'], motor['fc']
    print(f"[*] CharacterMotor ALL {fc} fields (field_start={fs}):")
    for fi in range(fc):
        abs_fi = fs + fi
        b = fdef_off + abs_fi * FD_SIZE
        try:
            ni, w1, w2 = struct.unpack_from("<III", meta, b)
            nm = cstr(ni) if ni < str_sz else f"<OOB:{ni:#x}>"
        except:
            nm, w1, w2 = "<err>", 0, 0
        p11  = _p11(abs_fi)
        mark = " ◄ LANE" if any(k in nm.lower() for k in LANE_KW) else ""
        p11s = f"  p11={p11:#010x}" if p11 is not None else ""
        print(f"  [{abs_fi:5d}/{fi:3d}] {nm:<40} | "
              f"w1={w1:#010x}  w2={w2:#010x}{p11s}{mark}")
else:
    print("[*] CharacterMotor: sentinel field_start or not found — skipping")

# ── ELF scan ──────────────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("[*] ELF symbol scan (libil2cpp.so)...")

def elf_scan(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        print("  not ARM64 ELF64 LE"); return []

    # ELF64 header fields starting at byte 16
    (etype, emach, ever, eentry, ephoff, eshoff,
     eflags, eehsz, ephentsz, ephnum,
     eshentsz, eshnum, eshstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    print(f"  e_machine={emach:#x} (0xb7=AArch64)  "
          f"e_shoff={eshoff:#x}  e_shnum={eshnum}  "
          f"e_shentsize={eshentsz}  e_shstrndx={eshstrndx}")

    if not eshoff or not eshnum:
        print("  no section header table"); return []
    if eshentsz != 64:
        print(f"  unexpected e_shentsize={eshentsz} (expected 64)"); return []
    if not (0 < eshstrndx < eshnum):
        print(f"  bad e_shstrndx={eshstrndx}"); return []

    def _shdr_base(i): return eshoff + i * 64

    # section name string table
    shstr_off, shstr_sz = struct.unpack_from("<QQ", data, _shdr_base(eshstrndx) + 24)
    shstrtab = data[shstr_off:shstr_off + shstr_sz]

    SHT_SYMTAB = 2; SHT_DYNSYM = 11
    sym_secs = []
    for i in range(eshnum):
        sb = _shdr_base(i)
        sh_name, sh_type = struct.unpack_from("<II",  data, sb)
        sh_off,  sh_sz   = struct.unpack_from("<QQ",  data, sb + 24)
        sh_link,         = struct.unpack_from("<I",   data, sb + 40)
        sh_entsize,      = struct.unpack_from("<Q",   data, sb + 56)
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM): continue
        label = "DYNSYM" if sh_type == SHT_DYNSYM else "SYMTAB"
        print(f"  section[{i}] .{label}  "
              f"off={sh_off:#x}  sz={sh_sz:#x}  "
              f"entsize={sh_entsize}  strtab_link={sh_link}")
        sym_secs.append((label, sh_off, sh_sz, sh_link, sh_entsize))

    if not sym_secs:
        print("  no symbol tables — binary is stripped"); return []

    all_hits = []
    for label, sym_off, sym_sz, str_link, entsize in sym_secs:
        strtab_off, strtab_sz = struct.unpack_from("<QQ",
                                    data, _shdr_base(str_link) + 24)
        strtab = data[strtab_off:strtab_off + strtab_sz]
        n_syms = sym_sz // entsize
        print(f"\n  {label}: {n_syms} symbols")

        api_hits  = []   # il2cpp_field_*
        data_hits = []   # g_FieldOffset*
        il2cpp_total = 0

        for si in range(n_syms):
            sb = sym_off + si * entsize
            # ELF64 Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
            st_name,            = struct.unpack_from("<I", data, sb)
            st_value, st_size   = struct.unpack_from("<QQ", data, sb + 8)
            try:
                end = strtab.index(b'\x00', st_name)
                sn = strtab[st_name:end].decode('utf-8', 'replace')
            except Exception: continue

            if sn.startswith('il2cpp_'): il2cpp_total += 1
            if 'FieldOffset' in sn or 'g_FieldOffset' in sn:
                data_hits.append((sn, st_value, st_size))
            elif 'il2cpp_field' in sn.lower():
                api_hits.append((sn, st_value))

        print(f"  total il2cpp_ exports : {il2cpp_total}")

        if data_hits:
            print(f"  DATA (FieldOffset symbols):")
            for n, v, sz in data_hits:
                print(f"    {n:<60} @ {v:#018x}  sz={sz}")
                all_hits.append({'kind': 'data', 'name': n, 'addr': v, 'size': sz})
        else:
            print("  (no g_FieldOffset data symbols — table is internal / not exported)")

        if api_hits:
            print(f"  il2cpp_field_* exports ({len(api_hits)}):")
            for n, v in api_hits:
                print(f"    {n:<60} @ {v:#018x}")
                all_hits.append({'kind': 'api', 'name': n, 'addr': v})
        else:
            print("  (no il2cpp_field_* exports — "
                  "field offset must come from il2cpp_class_get_fields loop)")

    return all_hits

elf_hits = elf_scan(lib)

# ── save ──────────────────────────────────────────────────────────────────────
result = {
    'metadata_version': ver,
    'n_types': n_types,
    'n_fdefs': n_fdefs,
    'cic':     cic,
    'motor':   motor,
    'lane_hits':  lane_hits,
    'elf_hits':   elf_hits,
}
with open(OUT, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n{'='*70}")
print(f"[*] SUMMARY  →  {OUT}")
print(f"    lane_hits  : {len(lane_hits)}")
for h in lane_hits:
    print(f"      abs_fi={h['abs_fi']}  '{h['name']}'  "
          f"{h['ns']}.{h['cls']}  typedef_idx={h['ti']}")
print(f"    elf_hits   : {len(elf_hits)}")
print()
if lane_hits:
    print("    Next: use abs_fi in the injected DLL —")
    print("      il2cpp_class_get_fields(klass, &iter) to walk fields")
    print("      il2cpp_field_get_name(fi) to match by name")
    print("      il2cpp_field_get_offset(fi) for the runtime object offset")
else:
    print("    No lane field found — check the fallback output above.")
    print("    Field might be named _currentColumn / _currentPosition / etc.")
    print("    Consider running Il2CppDumper for a full dump.cs to grep.")