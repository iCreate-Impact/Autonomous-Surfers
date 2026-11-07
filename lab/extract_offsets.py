#!/usr/bin/env python3
"""
extract_offsets.py v12

Three investigations:

  1. FS_OFF PROBE — exhaustive (fs_off, fc_off, fc_width) search over all 20,393
     typedefs to find any combo that maps a typedef to lane abs_fi targets
     {735, 780, 781, 3004, 3047, 3831}.  If nothing covers 3004/3047, those
     fields belong to classes with genuinely-sentinel FS regardless of offset.

  2. RAW TYPEDEF DUMP — print all 22 uint32 slots (88 bytes) for:
       · CharacterMotor (td[214]) — our verified reference
       · CharacterInputController (td[199])
       · Every typedef between them (td[196..215]) — multi-column summary
     This shows exactly which slot holds fieldStart / fieldCount for each type.

  3. PAIR TABLE SCAN — print ALL pairs [0..35] with sizes/entry-counts.
     pair[20] has only 845 entries; parent TypeIndex 23106/23113 need a table
     with >= 23114 entries.  Also probe each candidate pair entry for CIC/Motor
     parent_tidx (23106 / 23113) to confirm the right Il2CppType[] layout.

  4. FULL il2cpp_ DYNSYM — all 241 exported il2cpp_* symbols with vaddrs so we
     know exactly which API the C++ resolver can call.

Confirmed from v11:
  pair[2]=str  pair[10]=fdef(12B)  pair[11]=foff  pair[19]=typedef(88B n=20393)
  FS_OFF=32 · FC_OFF=64 — correct for CharacterMotor (fs=4055 fc=136 verified)
  laneIndex (abs_fi=3047) w1=0x08000bea w2=0x773b — no owner in reverse map
  currentLane (abs_fi=3004) w1=0x08000bbf w2=0x7723 — no owner in reverse map
  CIC td[199]: fs=SENTINEL fc=3 pt=23106
  Motor td[214]: fs=4055 fc=136 pt=23113

Usage: py -3 extract_offsets.py base.apk
Out:   probe_results.json
"""

import sys, zipfile, struct, json, collections

APK = sys.argv[1] if len(sys.argv) > 1 else "base.apk"
OUT = "probe_results.json"

LANE_TARGETS = {735: 'laneOffset', 780: 'laneDir_a', 781: 'laneDir_b',
                3004: 'currentLane', 3047: 'laneIndex', 3831: 'laneDir_c'}

STR_PI = 2; FDEF_PI = 10; FOFF_PI = 11; TYPE_PI = 19

TD_SIZE = 88; FD_SIZE = 12; SENTINEL = 0xFFFF_FFFF

# ── load ──────────────────────────────────────────────────────────────────────
print(f"[*] opening {APK}")
with zipfile.ZipFile(APK) as z:
    names = z.namelist()
    lib   = z.read(next(n for n in names if n.endswith("arm64-v8a/libil2cpp.so")))
    meta  = z.read(next(n for n in names if n.endswith("global-metadata.dat")))

magic, ver = struct.unpack_from("<II", meta, 0)
assert magic == 0xFAB11BAF
print(f"[*] metadata v{ver}  lib={len(lib):,}B  meta={len(meta):,}B")

def _pair(i): return struct.unpack_from("<II", meta, 8 + i * 8)

str_off,  str_sz  = _pair(STR_PI)
type_off, type_sz = _pair(TYPE_PI)
n_types = type_sz // TD_SIZE
n_fdefs = _pair(FDEF_PI)[1] // FD_SIZE
print(f"[*] n_types={n_types}  n_fdefs={n_fdefs}")

STR = meta[str_off:str_off + str_sz]
def cstr(r):
    if r >= str_sz: return f"<OOB:{r:#x}>"
    try: e = STR.index(b'\x00', r); return STR[r:e].decode('utf-8','replace')
    except ValueError: return STR[r:].decode('utf-8','replace')

def td_full_name(i):
    if not (0 <= i < n_types): return f"<OOB:{i}>"
    b = type_off + i * TD_SIZE
    ni, nsi = struct.unpack_from("<II", meta, b)
    return f"{cstr(nsi)}.{cstr(ni)}"

# ── 1. FS_OFF PROBE ───────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("[*] FS_OFF PROBE: searching all (fs_off, fc_off, fc_width) for typedefs")
print(f"    covering lane targets: {sorted(LANE_TARGETS)}")
print("    fc > 20000 excluded as noise")
print()

# offsets to try
FS_CANDS = range(28, 56, 4)   # 28, 32, 36, 40, 44, 48, 52
FC_CANDS = [(56,'H'),(60,'H'),(64,'H'),(68,'H'),(72,'H'),(76,'H'),
            (60,'I'),(64,'I'),(68,'I')]

# build a quick raw slot table for all typedefs to avoid re-reading meta
# store slots 7..13 (offsets 28..52) as uint32 and slots 14..20 as uint16
# for speed, pre-read relevant byte ranges

# Fast inner loop: pre-slice the typedef table
td_data = meta[type_off:type_off + n_types * TD_SIZE]

def td_u32(i, off): return struct.unpack_from("<I", td_data, i*TD_SIZE + off)[0]
def td_u16(i, off): return struct.unpack_from("<H", td_data, i*TD_SIZE + off)[0]

probe_hits = collections.defaultdict(list)  # key → list of (target, td_idx, fs, fc)

for fs_off in FS_CANDS:
    for fc_off, fc_fmt in FC_CANDS:
        for i in range(n_types):
            fs = td_u32(i, fs_off)
            if fs == SENTINEL or fs > 150000: continue
            fc = (td_u16(i, fc_off) if fc_fmt == 'H' else td_u32(i, fc_off))
            if fc == 0 or fc > 20000: continue
            for target in LANE_TARGETS:
                if fs <= target < fs + fc:
                    probe_hits[(fs_off, fc_off, fc_fmt)].append((target, i, fs, fc))

if not probe_hits:
    print("  *** NO COMBINATION FOUND ***")
    print("  Those fields truly belong to classes with sentinel at every")
    print("  candidate fieldStart offset.  See raw typedef dump below for")
    print("  manual inspection of CIC's raw slots.")
else:
    important = {k: v for k, v in probe_hits.items()
                 if any(h[0] in (3004, 3047) for h in v)}
    all_keys = sorted(important) if important else sorted(probe_hits)
    for key in all_keys:
        fs_off, fc_off, fc_fmt = key
        hits = probe_hits[key]
        targets_hit = sorted({h[0] for h in hits})
        marker = "  ◄ LANE INDEX" if 3047 in targets_hit else ""
        print(f"  FS_OFF={fs_off}  FC_OFF={fc_off}({fc_fmt})"
              f"  → covers abs_fi={targets_hit}{marker}")
        for target, td_idx, fs, fc in sorted(hits):
            print(f"    abs_fi={target:5d} ({LANE_TARGETS[target]:<12})  "
                  f"typedef[{td_idx:5d}] '{td_full_name(td_idx)}'  "
                  f"fs={fs}  fc={fc}")
        print()

print(f"[*] checked {len(FS_CANDS)*len(FC_CANDS)} offset combos × {n_types} typedefs")

# ── 2. RAW TYPEDEF DUMP ───────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("[*] RAW TYPEDEF DUMP")
print("    Slot layout (each slot = 4 bytes):")
print("    [0]nameIdx [1]nsIdx [2]byvalTI [3]byrefTI [4]declaringTI [5]parentTI")
print("    [6]elemTI [7]genContainerIdx [8]??? [9]??? [10]??? [11]??? ...")
print("    FC_OFF=64 → slot 16;  FS_OFF=32 → slot 8;  PARENT_OFF=20 → slot 5")

for label, td_idx in [("CharacterMotor (reference)", 214), ("CIC", 199)]:
    slots = [td_u32(td_idx, k*4) for k in range(22)]
    print(f"\n  typedef[{td_idx}] {label}:")
    print(f"  fullname: {td_full_name(td_idx)}")
    for k in range(0, 22, 4):
        row = slots[k:k+4]
        hexs = "  ".join(f"[{k+j:2d}]{v:#010x}" for j,v in enumerate(row))
        print(f"    {hexs}")
    # specifically call out slots that differ between the two
    print(f"  → slot[8]={slots[8]}  slot[9]={slots[9]}  slot[10]={slots[10]}")
    print(f"  → slot[14]={slots[14]}  slot[15]={slots[15]}  slot[16]={slots[16]}")
    print(f"  → slot[17]={slots[17]}  slot[18]={slots[18]}")

# typedefs 196–215: multi-column summary showing key slot offsets
print(f"\n  Typedefs 196–215 — multi-offset comparison (uint32 @28,32,36; uint16 @60,64,68,72):")
header = (f"  {'idx':>4}  "
          f"{'@28':>10}  {'@32':>10}  {'@36':>10}  "
          f"{'fc@60':>6}  {'fc@64':>6}  {'fc@68':>6}  {'fc@72':>6}  "
          f"name")
print(header)
print("  " + "-"*120)
for td_idx in range(196, 216):
    if td_idx * TD_SIZE + TD_SIZE > len(td_data): break
    v28, v32, v36  = td_u32(td_idx, 28), td_u32(td_idx, 32), td_u32(td_idx, 36)
    f60, f64, f68, f72 = (td_u16(td_idx, o) for o in (60, 64, 68, 72))
    name = td_full_name(td_idx)
    # mark CIC and Motor
    mark = " ◄" if td_idx in (199, 214) else ""
    # flag any slot that looks like it could be fieldStart covering 3047
    fs_flag = ""
    for v in (v28, v32, v36):
        if v != SENTINEL and 2000 <= v <= 3047:
            fs_flag = f"  ** @28/32/36={v} near 3047"
    print(f"  [{td_idx:4d}]{mark}  "
          f"{v28:#010x}  {v32:#010x}  {v36:#010x}  "
          f"{f60:6d}  {f64:6d}  {f68:6d}  {f72:6d}  "
          f"{name[:50]}{fs_flag}")

# also dump raw slots for typedefs that contain each lane field (from reverse-map hits)
# i.e. typedefs whose FS_OFF=32 field_start + fc covers our targets but maybe with wrong fc
print(f"\n  Additional: check raw slots for any typedef where slot[8] (FS_OFF=32)")
print(f"  is in range [2000, 4055) — might have wrong fc at FC_OFF=64:")
for td_idx in range(n_types):
    fs = td_u32(td_idx, 32)   # slot 8
    if 2000 <= fs < 4055:
        fc_at_64 = td_u16(td_idx, 64)
        fc_at_68 = td_u16(td_idx, 68)
        fc_at_72 = td_u16(td_idx, 72)
        for target in (3004, 3047):
            if fc_at_64 > 0 and fs <= target < fs + fc_at_64: continue  # already in probe
        # print if fc@64 is 0 or unreasonably small
        if fc_at_64 < 10:
            print(f"    td[{td_idx:5d}] fs@32={fs:6d}  fc@64={fc_at_64:5d}  "
                  f"fc@68={fc_at_68:5d}  fc@72={fc_at_72:5d}  {td_full_name(td_idx)}")

# ── 3. PAIR TABLE SCAN ────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("[*] PAIR TABLE [0..35]")
print("    CIC parent_tidx=23106  Motor parent_tidx=23113")
print("    Need a table with >= 23114 entries of 8B = 184,912B  or 12B = 277,368B")
print()

PARENT_TIDXS = {23106: 'CIC_parent', 23113: 'Motor_parent'}
IL2CPP_CLASS = 0x11; IL2CPP_VT = 0x12

for pi in range(36):
    off, sz = _pair(pi)
    if off == 0 and sz == 0: continue
    flags = []
    n8  = sz // 8
    n12 = sz // 12
    n4  = sz // 4
    if n8  >= 23114: flags.append("← Il2CppType[] esz=8 candidate")
    if n12 >= 23114 and not flags: flags.append("← Il2CppType[] esz=12 candidate")

    # probe parent_tidx entries if size allows
    extra = []
    for tidx, label in PARENT_TIDXS.items():
        for esz in (8, 12):
            n = sz // esz
            if tidx >= n: continue
            b = off + tidx * esz
            if b + 8 > len(meta): continue
            data_val, attrs, te = struct.unpack_from("<IHB", meta, b)
            if te in (IL2CPP_CLASS, IL2CPP_VT):
                extra.append(f"  entry[{tidx}]({label}) esz={esz}: "
                              f"data={data_val:#x} te={te:#04x} attrs={attrs:#x}")

    flag_str = "  " + "  ".join(flags) if flags else ""
    print(f"  pair[{pi:2d}]: off={off:#010x}  sz={sz:#010x}  "
          f"/4={n4:7d}  /8={n8:7d}  /12={n12:7d}{flag_str}")
    for e in extra:
        print(f"           {e}")

# ── 4. FULL il2cpp_ DYNSYM DUMP ───────────────────────────────────────────────
print(f"\n{'='*70}")
print("[*] FULL il2cpp_ DYNSYM DUMP")

def parse_dynsym(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1: return []
    (etype, emach, ever, eentry, ephoff, eshoff,
     eflags, eehsz, ephentsz, ephnum,
     eshentsz, eshnum, eshstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if not eshoff or not eshnum or eshentsz != 64: return []
    if not (0 < eshstrndx < eshnum): return []
    def _shdr(i): return eshoff + i * 64
    shstr_off, shstr_sz = struct.unpack_from("<QQ", data, _shdr(eshstrndx)+24)
    shstrtab = data[shstr_off:shstr_off+shstr_sz]
    SHT_DYNSYM = 11
    for i in range(eshnum):
        sh_name, sh_type = struct.unpack_from("<II", data, _shdr(i))
        if sh_type != SHT_DYNSYM: continue
        sh_off, sh_sz  = struct.unpack_from("<QQ", data, _shdr(i)+24)
        sh_link,       = struct.unpack_from("<I",  data, _shdr(i)+40)
        sh_entsize,    = struct.unpack_from("<Q",  data, _shdr(i)+56)
        strtab_off, strtab_sz = struct.unpack_from("<QQ", data, _shdr(sh_link)+24)
        strtab = data[strtab_off:strtab_off+strtab_sz]
        syms = []
        for si in range(sh_sz // sh_entsize):
            sb = sh_off + si * sh_entsize
            st_name, = struct.unpack_from("<I", data, sb)
            st_value, = struct.unpack_from("<Q", data, sb + 8)
            st_size,  = struct.unpack_from("<Q", data, sb + 16)
            try:
                e = strtab.index(b'\x00', st_name)
                sn = strtab[st_name:e].decode('utf-8','replace')
            except: continue
            if sn.startswith('il2cpp_'): syms.append((sn, st_value, st_size))
        return syms
    return []

syms = parse_dynsym(lib)
syms.sort(key=lambda x: x[0])
print(f"  total il2cpp_ exports: {len(syms)}")
print()

# print in columns, grouping by subsystem (il2cpp_domain_, il2cpp_class_, etc.)
GROUPS = ['domain','assembly','image','class','field','method','type','thread',
          'gc','object','value','array','string','monitor','alloc','mem']
grouped = collections.defaultdict(list)
for name, addr, sz in syms:
    placed = False
    for g in GROUPS:
        if f'il2cpp_{g}_' in name or name == f'il2cpp_{g}':
            grouped[g].append((name, addr))
            placed = True; break
    if not placed:
        grouped['other'].append((name, addr))

for grp in GROUPS + ['other']:
    if grp not in grouped: continue
    print(f"  — {grp} ({len(grouped[grp])}) —")
    for name, addr in grouped[grp]:
        print(f"    {name:<52} {addr:#018x}")
    print()

# ── save ──────────────────────────────────────────────────────────────────────
result = {
    'probe_hits_covering_3047': [
        {'key': str(k), 'hits': [{'abs_fi':h[0],'td_idx':h[1],'fs':h[2],'fc':h[3]}
                                   for h in v]}
        for k, v in probe_hits.items()
        if any(h[0] in (3004, 3047) for h in v)
    ],
    'il2cpp_exports': [{'name': n, 'addr': a} for n, a, _ in syms],
}
with open(OUT, 'w') as f: json.dump(result, f, indent=2)
print(f"[*] written to {OUT}")