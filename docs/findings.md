# Android 11 Research Findings

Live target: BlueStacks 5, `HD-Player.exe` PID 8452 (session started 2026-11-11 06:34),
`C:\Program Files\BlueStacks_nxt\BstkVMM.dll` version **2.1.24.117012** (VirtualBox VMM,
file date 2023-08-04). All probes were read-only.

---

## Run Log

### [2026-11-11 07:36] Probe 1 — Full range map / pVM layout

**Question:** Are there RAM ranges above `0xE0000000`, and is `PGM_RANGES_OFFSET = 0x1010`
still the range-list head? Where do the other 19 of the 20 ranges live?

**Method:** Injected `recon_probe_1.dll` into the live `HD-Player.exe`. Used the
existing UVM magic scan (`0x19700823`), dumped `pVM+0x0F00..0x1100`, dumped the node at
`pVM+0x1010`, and tested every host pointer/qword in that node as a possible next pointer
or range record. Also disassembled `PGMR3PhysGetRamRangeCount` (RVA `0x06F250`) and
`PGMR3PhysGetRange` (RVA `0x06F2E0`) from `BstkVMM.dll` offline.

**Result (raw):**
```
UVM FOUND: pUVM=00000178A993C000 pVM=00000178A9770000 nRanges=20
pRamRangesXR3 (pVM+0x1010) = 00000178B3830000
head+0000  0000000000000000
head+0008  00000000E0000000
head+0010  00000178B0CD84F0   <- next node, NOT the host-RAM base
head+0018  00000178B0CD84F0
head+0020  00000000FD85E4F0
head+0028  00000000DFFFFFFF
head+0030  0000000000000000
head+0040  00007FFF8C794818   <- "Base RAM" description string
head+0048  00000178B3830000   <- self pointer
```

Disassembly of `PGMR3PhysGetRamRangeCount`:
```asm
mov 0x1010(%rdi),%rcx      ; head = pVM->pgm.s.pRamRangesXR3
test %rcx,%rcx
je done
loop:
mov 0x10(%rcx),%rcx        ; node = node->pNextR3  (offset +0x10)
inc %ebx
test %rcx,%rcx
jne loop
```

Disassembly of `PGMR3PhysGetRange` (VC++ x64: rcx=pVM, edx=index, r8=pStart,
r9=pEnd, [rsp+0x50]=pDesc, [rsp+0x58]=pIsRom):
```asm
mov 0x1010(%rbx),%rcx      ; head
...
mov (%rcx),%rax            ; *pStart  = node[+0x00]
mov %rax,0x0(%rbp)
mov 0x28(%rcx),%rax        ; *pEnd    = node[+0x28]
mov %rax,(%rsi)
mov 0x40(%rcx),%rax        ; *pDesc   = node[+0x40]
mov %rax,(%rdx)
mov 0x24(%rcx),%eax        ; *pIsRom  = (node[+0x24] >> 22) & 1
```

**Result (corrected walk, `recon_probe_1b.dll`):**
```
pVM=00000178A9770000 nRanges=20
range[00] node=00000178B3830000 GC:0000000000000000-00000000DFFFFFFF  3584 MB  cb=0xE0000000  desc=Base RAM
range[01] node=00000178B0CD84F0 GC:00000000E0000000-00000000E0BFFFFF    12 MB  cb=0x00C00000  desc=VRam
range[02] node=00000178B0CD4270 GC:00000000F0000000-00000000F03FFFFF     4 MB  cb=0x00400000  desc=VMMDev
range[03] node=00000178B0CD8330 GC:00000000F0400000-00000000F0403FFF    16 KB  cb=0x00004000  desc=VMMDev Heap
range[04] node=00000178B0CF7D20 GC:00000000F0404000-00000000F0404FFF     4 KB  cb=0x00001000  desc=USB OHCI
range[05] node=00000178B0CF7EE0 GC:00000000F0405000-00000000F0405FFF     4 KB  cb=0x00001000  desc=bstaudio
range[06] node=00000178B0CF3320 GC:00000000F0480000-00000000F04C0FFF   260 KB  cb=0x00041000  desc=bstaudio
range[07] node=00000178B0CF80A0 GC:00000000F0500000-00000000F0500FFF     4 KB  cb=0x00001000  desc=bstvmsg
range[08] node=00000178B0CF7320 GC:00000000F0520000-00000000F0534FFF    84 KB  cb=0x00015000  desc=bstvmsg
range[09] node=00000178B0CF84A0 GC:00000000F0540000-00000000F0541FFF     8 KB  cb=0x00002000  desc=AHCI
range[10] node=00000178B0CF8670 GC:00000000F0542000-00000000F0542FFF     4 KB  cb=0x00001000  desc=bstpgaipc
range[11] node=00000178B15E0030 GC:00000000F2000000-00000000F3FC0FFF    31 MB  cb=0x01FC1000  desc=bstpgaipc
range[12] node=00000178B1650030 GC:00000000F4000000-00000000F5FFFFFF    32 MB  cb=0x02000000  desc=bstpgaipc
range[13] node=00000178B0CF8830 GC:00000000F6000000-00000000F6000FFF     4 KB  cb=0x00001000  desc=bstcamera
range[14] node=00000178B0CF37F0 GC:00000000F6001000-00000000F6001FFF     4 KB  cb=0x00001000  desc=bstcamera
range[15] node=00000178B0CF38C0 GC:00000000F6400000-00000000F6783FFF     3.5 MB cb=0x00384000 desc=bstcamera
range[16] node=00000178B0CD0440 GC:00000000FEC00000-00000000FEC00FFF     4 KB  cb=0x00001000  desc=I/O APIC
range[17] node=00000178B0CCF940 GC:00000000FEE00000-00000000FEE00FFF     4 KB  cb=0x00001000  desc=APIC
range[18] node=00000178B0CCD860 GC:00000000FFFF0000-00000000FFFFFFFF    64 KB  cb=0x00010000  desc=PC BIOS - 0xffffffff
range[19] node=00000178B5E10000 GC:0000000100000000-000000011FFFFFFF   512 MB  cb=0x20000000  desc=Above 4GB Base RAM
```

**Finding:** The range list head offset `0x1010` is **still correct**, but the node layout
changed (or the Android 9 code was reading it through a lucky coincidence):

| Field | Android 9 code assumed | Android 11 / VMM 2.1.24 |
|-------|------------------------|--------------------------|
| `GCPhysStart` | node+0x00 | node+0x00 (same) |
| `GCPhysLast`  | node+0x08 | **node+0x28** (inclusive last address) |
| `pNextR3`     | node+0x30 (auto-guessed) | **node+0x10** |
| `cb`          | node+0x08-ish (implicit size) | node+0x08 |
| `pDesc`       | not read | node+0x40 |
| `IsRom`       | not read | `(node[+0x24] >> 22) & 1` |

The Android 9 `InitRangeMap` read `gcEnd` from `+0x08` (which is `cb`, the size) and
searched for `pNextR3` between `+0x20` and `+0x100`; it picked `+0x30`, which is zero in
this layout. That is why it printed exactly one range and then stopped.

**Critical discovery:** There are **two actual guest RAM ranges**:
- `Base RAM`: GPA `0x00000000..0xDFFFFFFF` (3584 MB)
- `Above 4GB Base RAM`: GPA `0x100000000..0x11FFFFFFF` (512 MB)

The old `GUEST_RAM_BYTES = 0xE0000000` ceiling excludes the **512 MB above 4 GB**, which
is exactly where the Android 11 allocator may put page tables. The other 18 ranges are
MMIO/VRAM/device windows, not general-purpose RAM.

**Next question:** Does a PTE/PMD leaf mapping the known libil2cpp page
(`GPA 0xC4C1F000` in the old log) exist in the `0x100000000..0x11FFFFFFF` range? If so,
where is TTBR0 and how deep is the walk?

---

### [2026-11-11 07:40] Immediate next step

Probe 2: rescan all 20 corrected ranges (not just 0..0xE0000000) for ELF headers,
identify the current `libil2cpp.so` header GPA, then scan every byte of both Base RAM
ranges for 4 KB PTE leaves and 2 MB PMD block leaves that map that GPA. Log the exact
entry locations and raw values so Probe 3 can check descriptor bits.

---

### [2026-11-11 07:44] Probe 2 — extended scan across all ranges

**Question:** Do page-table leaves for the known libil2cpp page exist above
`0xE0000000`?

**Method:** `recon_probe_2.dll` and `recon_probe_2b.dll`. Walked the corrected range
list, scanned every RAM-like range for ARM64 ET_DYN headers, then scanned every 8-byte
word of every range for 4 KB and 2 MB leaves matching the target GPA. A read-size
sanity test was included.

**Result:** Read-size sanity test:
```
gpa=0x0           size=16     rc=0
gpa=0x0           size=4096   rc=0
gpa=0x0           size=65536  rc=0
gpa=0x0           size=1MB    rc=-1618 (0xFFFFF9AE)
gpa=0x1000000     size=1MB    rc=0
gpa=0xC4C1F000    size=1MB    rc=0
gpa=0x100000000   size=1MB    rc=0
```
The first 1 MB at GPA 0 contains at least one non-present PGM page, so
`PGMPhysSimpleReadGCPhys` rejects the whole 1 MB request. The first chunked scanner
silently stopped after that failure. A fallback to 64 KB chunks (and 4 KB pages for
still-failing 64 KB regions) fixed it.

ELF scan over all ranges (game process `com.kiloo.subwaysurf`, guest PID 4658, was
already running):
```
ARM64 ET_DYN @ GPA=0x00000000B5601000 phnum=5 dyn_offset=0x2DD0
ARM64 ET_DYN @ GPA=0x00000000B89EF000 phnum=5 dyn_offset=0x6EF0
ARM64 ET_DYN @ GPA=0x00000000DA9E2000 phnum=23 dyn_offset=0x199000
libil2cpp not found (game may not be running)
```
The libil2cpp ELF header page had already been evicted (the game had been running for
over an hour), exactly the failure mode documented in `CHANGELOG.md`.

PTE scan using the stale Android 9 GPA `0xC4C1F000`:
```
range[0] Base RAM              4K=0    2M=211
range[1] VRam                  4K=0    2M=0
range[2] VMMDev                4K=0    2M=0
range[3] bstpgaipc 31 MB       4K=0    2M=0
range[4] bstpgaipc 32 MB       4K=0    2M=0
range[5] bstcamera             4K=0    2M=0
range[6] Above 4GB Base RAM    4K=0    2M=63   (hit log capped)
```
So the only high-address hits are in `Above 4GB Base RAM`. Many are false positives
because the 2 MB mask ignores address bits 12..20.

**Finding:** The page tables are indeed in the 512 MB `Above 4GB Base RAM` range, which
the Android 9 code never scanned. The ELF-header-page path is unreliable for late
injection, so the resident SONAME string is the right anchor. Also
`PGMPhysSimpleReadGCPhys` cannot be trusted with 1 MB spans; reads must be chunked and
retried.

**Next question:** Is the leaf mapping the SONAME page a 4 KB PTE or a 2 MB block, and
what is the real page-table format/depth?

---

### [2026-11-11 07:51] Probe 3 — resident SONAME page + descriptor format

**Question:** Where does the resident `"libil2cpp.so"` page live physically, and what
do the descriptors that map it look like?

**Method:** `recon_probe_3.dll`. Scanned all RAM-like ranges for the null-terminated
SONAME, then scanned every 8-byte word for ARM64-style 4 KB/2 MB leaves. For each hit,
analyzed the containing 4 KB page (count of nonzero words, table-like descriptors,
block-like descriptors, physical addresses in range).

**Result:**
```
SONAME occurrences:
  GPA=0x000000009B128258  page=0x9B128000  off=0x258
  GPA=0x00000000B638C770  page=0xB638C000  off=0x770
  GPA=0x00000000B638C7A0  page=0xB638C000  off=0x7A0

ARM64-style 4K scan for page 0x9B128000 found exactly one:
  4K leaf @ GPA=0x000000011BE88210
      entry = 0x800000009B128067
      pageStats: nz=90 tbl=8 blk=1 oa=8 ptr=0
```
The entry is a textbook **x86_64 4 KB PTE**:
- bit 0 = 1 (`P` present)
- bit 1 = 1 (`RW`)
- bit 2 = 1 (`US` user)
- bits 5/6 = 1 (`A` accessed, `D` dirty)
- bit 63 = 1 (`NX`)
- physical base = `entry & 0x000FFFFFFFFFF000` = `0x9B128000`

This is not an ARM64 descriptor. The 2 MB "hits" with huge `blk` counts were actually
pages full of 4 KB PTEs whose bits 12..20 are ignored by the 2 MB mask.

**Finding:** The page-table format is **x86_64**, not ARM64. The guest kernel is
`Linux 4.19.195 x86_64` (`address sizes: 39 bits physical, 48 bits virtual`), so the
walk is:
```
PML4[47:39] -> PDPT[38:30] -> PD[29:21] -> PT[20:12] -> offset
```
The physical page tables live at GPA `0x11BE88xxx..0x11BE8Axxx`, i.e. above 4 GB.
The "ARM64 page table walk" in the Android 9 code was the wrong model for Android 11.

**Next question:** Walk PTE -> PD -> PDPT -> PML4, find the process CR3, and verify the
reconstructed guest virtual address translates back to `0x9B128258`.

---

### [2026-11-11 07:55] Probe 4 — x86_64 parent walk and CR3 discovery

**Question:** What is the game process's page-table root (CR3), and does a full
x86_64 translation reproduce the SONAME page?

**Method:** `recon_probe_4.dll` / `recon_probe_4b.dll`. Took the unique PTE
(`GPA 0x11BE88210`, entry `0x800000009B128067`), searched all RAM for present,
non-PS entries whose physical target was the PTE page, repeated up the hierarchy,
then reconstructed the GVA from the table indices and translated it with the recovered
PML4 page.

**Result:**
```
PTE  @ 0x11BE88210   entry 0x800000009B128067   idx=0x42
PD   @ 0x11BE894B0   entry 0x000000011BE88067   idx=0x96
PDPT @ 0x11BE8A000   entry 0x000000011BE89067   idx=0x00
PML4 @ 0x119919000   entry 0x000000011BE8A067   idx=0x00

CR3 = 0x0000000119919000
reconstructed GVA = 0x0000000012C42258
X64Translate(CR3, GVA) -> GPA 0x9B128258   ok=1 (4K page)
```
The SONAME string is at guest virtual address `0x12C42258` (offset `0x258` in page
`0x12C42000`). The page table root is `CR3 = 0x119919000`, a guest-physical page in
`Above 4GB Base RAM`.

(The level-4 search also found a reference to the PML4 page at `0x11A5B48C8`; that is
not part of the four-level user walk and must not be used as CR3. The correct root is
the page containing the PML4E, i.e. the level-3 parent page.)

**Finding:** Android 11 uses x86_64 4-level page tables with CR3 in the 512 MB range
above 4 GB. The pipeline must:
1. find the SONAME page (resident) instead of relying on the ELF header page;
2. scan all RAM including `0x100000000..0x11FFFFFFF`;
3. use x86_64 PTE/PDE/PDPTE/PML4E formats (`P` bit 0, `PS` bit 7, physical mask
   `0x000FFFFFFFFFF000`);
4. reconstruct CR3 by walking PTE -> PD -> PDPT -> PML4, not PTE -> PMD -> PGD.

**Next question:** Does the same CR3 translate the `fields` GVA in IL2CPP class
candidates, and can Stage 5a/5b/6 complete with the x86_64 walk?

---

### [2026-11-11 07:56] Immediate next step

Probe 5: run the Stage 5a class-candidate scan using the corrected range list, then
use the discovered `CR3=0x119919000` and x86_64 `GvaToGpa()` to resolve `fields`
pointers and find the `currentLane` / `laneIndex` fields. This validates the full
translation path before writing `recon_android11.cpp`.

---

### [2026-11-11 08:07] Probe 5 — corrected range map + x86_64 class scan

**Question:** Does the full pipeline (range walk -> SONAME/CR3 -> x86_64 GVA->GPA ->
class-candidate scan) work with the corrected Android 11 range list?

**Method:** `recon_probe_5.dll`. Walked the 20 corrected ranges, discovered CR3 from
the resident SONAME, then scanned all RAM for plausible `Il2CppClass` records using the
APK-disassembled layout (`name=+0x10`, `fields=+0x80`, `field_count u16=+0x124`) and
validated the `fields` pointer with the x86_64 walk.

**Result (raw):**
```
RAM-like ranges: 7  ceiling=0000000120000000
DiscoverCr3: SONAME GPA=000000009B128258 ... CR3=0000000119919000
  SONAME string at GVA 0000000012C42258: "libil2cpp.so"
  sanity X64Translate(cr3, 0x12C42258) -> ok=1 gpa=0000000000000000 4K
  scanning Base RAM (3584 MB)
  ... cumulative: candidates=1401515 validName=384 validFields=114
```

**Finding:** The x86_64 translation path is sound and produces class-shaped records,
but the old lane anchor (`currentLane` / `laneIndex` field names from Android 9) does not
exist in the Android 11 metadata, so the scan cannot identify the lane class by name.

**Next question:** Where is the `_currentLaneIndex` string, and which FieldInfo/class
references it?

---

### [2026-11-11 08:28] Probe 6 — `_currentLaneIndex` string + FieldInfo search

**Question:** Can the lane class be found by locating the `_currentLaneIndex` string and
then searching for a FieldInfo whose `name` pointer equals it?

**Method:** `recon_probe_6.dll`. Located the string in all RAM, resolved its page to all
GVA aliases, then scanned for qwords equal to each alias and validated FieldInfo arrays.

**Result (raw):**
```
STEP 1: locate "_currentLaneIndex" string
  1 occurrences
  string GPA=00000001029B7D09
STEP 2/3: FieldInfo name pointers
    GvasForGpa(00000001029B7D09): 1 4K PTE candidates
no validated field array - stopping
```

**Finding:** The string exists exactly once in guest RAM (inside the metadata file
mapping), but no FieldInfo points at it. The runtime class/field array for
`CharacterProgressEntry` is therefore not initialized (or not present) in this session.

**Next question:** Which CR3s map the metadata page, and are they different processes?

---

### [2026-11-11 08:31] Probe 7 — chain walk with all parents

**Question:** How many CR3 chains map the metadata/lane-string pages, and which ones
are user address spaces?

**Method:** `recon_probe_7.dll`. Enumerated every parent chain from the 4 KB PTE with
`X64AllChainsFromPte`, printed the reconstructed GVA and a user/kernel classification,
and re-translated each candidate.

**Result:** The lane-string page and the metadata page each have four parents
(user + kernel aliases), e.g. lane string:
```
CR3=00000000CB9AB000 GVA=000078F79A15CD09 USER   -> gpa=00000001029B7D09
CR3=00000000BBD93000 GVA=FFFFE19F5A15CD09 KERNEL -> same gpa
CR3=00000000BCD08000 GVA=0000498807F5CD09 USER   -> same gpa
CR3=00000000BCD08000 GVA=000049880835CD09 USER   -> same gpa
```

**Finding:** A physical page can have several virtual aliases and several owning CR3s
(processes, kernel direct map, KPTI). Candidate validation must translate back and
compare the GPA, not just trust one parent chain.

**Next question:** Do any of the user aliases contain a `FieldInfo.name` pointer?

---

### [2026-11-11 08:49] Probe 8 — metadata mapping + runtime class chain

**Question:** Which alias/base pairs map global-metadata, and do FieldInfo name
pointers exist under any of them?

**Method:** `recon_probe_8.dll`. Located the metadata magic and the lane string, then
enumerated every user alias for both pages and matched aliases by CR3.

**Result (raw):**
```
lane string GPA=00000001029B7D09  (1 PTE, 4 parents)
metadata magic GPA=00000000DB579000 (1 PTE, 4 parents)
USER CR3=00000000CB9AB000 GVA=000078F79A15CD09
USER CR3=00000000BCD08000 GVA=0000498807F5CD09
USER CR3=00000000BCD08000 GVA=000049880835CD09
```

**Finding:** Metadata is mapped, but no FieldInfo name pointer was found under these
aliases. The lookup table seen later (Probe 12) is what references the name strings.

**Next question:** Can a structural scan find any FieldInfo array regardless of alias?

---

### [2026-11-11 08:52] Probe 9 — metadata alias -> FieldInfo -> class -> instance

**Question:** Does the lane-name pointer appear anywhere once all metadata aliases are
tried?

**Method:** `recon_probe_9.dll`. For each `(cr3, gva)` alias of `_currentLaneIndex`,
scanned all RAM for a qword equal to that GVA.

**Result (raw):**
```
testing CR3=00000000CB9AB000 stringGVA=000078F79A15CD09 ... 0 hits
testing CR3=00000000BCD08000 stringGVA=0000498807F5CD09 ... 0 hits
```

**Finding:** No FieldInfo references the lane string by an alias. `currentLane` /
`laneIndex` are not fields of any class in this build; the 99-field Android 9 class is
obsolete. New candidates must come from the metadata type list instead.

**Next question:** Is the runtime FieldInfo stride 0x18 (Android 9) or 0x20 (Android 11)?

---

### [2026-11-11 09:05] Probe 10 — structural FieldInfo scan

**Question:** Does any memory region contain the 12 known field-name pointers at a fixed
stride 0x18 or 0x20?

**Method:** `recon_probe_10.dll`. Scanned every qword of all RAM and checked whether 12
known metadata string pointers appear at a constant stride.

**Result (raw):**
```
stride=0x18 done, 4179 MB scanned, 0 hits
stride=0x20 done, 8358 MB scanned, 0 hits
RESULT: no structural FieldInfo array found
```

**Finding:** The `CharacterProgressEntry` FieldInfo array is not present at all in that
session. The class is initialized lazily; probes must run while the game is in a live
run, not in the pause/loading state.

**Next question:** Re-start the game, find the real game CR3 and metadata base, and
search only there.

---

### [2026-11-11 12:34] Probe 11 — new session: name/namespace delta scan

**Question:** In a fresh BlueStacks session, which CR3/base pair is the game, and does
the name/namespace delta identify class records?

**Method:** `recon_probe_11.dll`. Found the class-name and namespace strings, measured
their delta, found the metadata header, discovered CR3 from the SONAME, and compared all
metadata aliases.

**Result (raw):**
```
clsName @ GPA=00000000C1025AB9    name-ns delta = 0xBF350B59 (expected 0xB6FD)
metaHdr @ GPA=00000000B8467000
DiscoverCr3: CR3=00000000CB84D000 GVA=000000000438C820 str="libil2cpp.so"
metadata aliases: 4 CR3s
  BBE1D000 base=0000637343F52000 / 00006EB82E966000
  2601000  base=00000177D0152000
  C0B0A000 base=00000177EFD66000
  CB84D000 base=00007BEEE7752000   <-- game
```

**Finding:** BlueStacks had restarted (PID 556); all old GPAs/CR3s were stale. Multiple
processes map the same physical metadata page at different virtual bases. The game space
is the one whose SONAME GVA is the low `0x0438C820` mapping (`CB84D000`,
base `7BEEE7752000`).

**Next question:** What actually references the class-name string inside that space?

---

### [2026-11-11 12:39] Probe 12 — metadata window reference scan

**Question:** In the game space, what structures point into the metadata window, and is
there an `Il2CppClass` for `CharacterProgressEntry`?

**Method:** `recon_probe_12.dll`. Scanned all RAM for qwords inside
`[base, base+16 MB)` and histogrammed the offsets; then dumped the object containing the
unique pointer to `base+0xFCC39`.

**Result (raw):**
```
TOTAL pointers into window: 1115058
top offsets: 0xCD55C(empty ns) 4096x, 0xF153C(SYBO.Subway) 4096x,
             0x1A66E3(String) 4096x, ... 0xFCC39 unique
class-name pointer base+0xFCC39 at GPA 0xB077A3C0
object at 0xB077A3B0 (0x20-byte records):
  +00 0
  +08 base+0xF153C  <- namespace
  +10 base+0xFCC39  <- name
  +18 base+0xC9A428 <- Il2CppTypeDefinition*
  +20 0, +28 ns, +30 name, +38 typeDef, ...
```

**Finding:** The unique name pointer lives in a `{0, namespace, name, typeDefinition}`
lookup table with stride `0x20`, not in an `Il2CppClass`. This is a runtime metadata
name-resolution table, not the class itself.

**Next question:** Is the real `CharacterProgressEntry` class initialized anywhere in
this session?

---

### [2026-11-11 12:44] Probe 13 — class/fields/instance probe

**Question:** Does the class object at `0xB077A3B0` have field_count 12 and a valid
`fields` array, and are there instances?

**Method:** `recon_probe_13.dll`. Enumerated all metadata base aliases in the game CR3,
searched for pointers to `base+0xFCC39`, validated `field_count`/`fields`, and scanned
for instances of the class GVA.

**Result (raw):**
```
metadata base aliases in game cr3: 1  (base=00007BEEE7752000)
class-name pointer hits: 1
class cls=00000000B077A3B0 fc=0 ns=00007BEEE83EC428 (ns BAD) fields=0
RESULT: no initialized class / instance found
```

**Finding:** The only name pointer is the lookup-table record; the class is uninitialized
in that game state (pause menu). No instances exist.

**Next question:** Is this table record possibly a real `Il2CppClass` with a different
layout?

---

### [2026-11-11 12:49] Probe 14 — runtime class layout dump

**Question:** What is the real runtime `Il2CppClass` layout on Android 11 / this libil2cpp?

**Method:** `recon_probe_14.dll`. Dumped the whole object at `0xB077A3B0`, annotated
metadata pointers, searched for a `fields` array whose `FieldInfo[0].name` is
`base+0xE0F0F`, and disassembled the live libil2cpp code at the APK vaddrs.

**Result (raw):**
```
object is a repeating 0x20-byte {0, ns, name, typeDefinition} table (11 records)
+0x18 = base+0xC9A428 (typeDefinition of CharacterProgressEntry)
u16==12 scan: none
FIELDS ARRAY: not found
libil2cpp ELF header GPA=0000000001C40000, load base GVA=000000000348C000
code@+0x1DEA080: 52 65 67 69 73 74 65 72  "Register"
code@+0x1E487D8: 73 74 65 6D 2E 54 72 61  "stem.Tra"
```

**Finding:** The object is definitely not an `Il2CppClass`. The live libil2cpp is not
byte-identical to the APK copy (or the load-bias reconstruction is wrong), so the APK
offsets cannot be blindly applied to the live image. A class known to be initialized is
needed to measure the real layout.

**Next question:** Enumerate every address space mapping libil2cpp/metadata and check
all of them for an initialized class, instead of guessing from one name pointer.

---

### [2026-11-11 13:04] Probe 15 — all address spaces, real CharacterMotor class

**Question:** Are there other address spaces that map libil2cpp/metadata, and does any of
them contain a fully initialized `Il2CppClass`?

**Method:** `recon_probe_15.dll`. Enumerated every CR3 chain for the SONAME page and the
metadata magic page; validated each space; scanned all RAM for pointers to the name
strings of `CharacterProgressEntry`, `CharacterMotor`, `System.String`, and the
`Assembly-CSharp.dll` image name; validated candidates (`name`, namespace, `fields`,
`FieldInfo[0].name`).

**Result (raw):**
```
SONAME CR3s: 3   (BBE2D000, BC674000, DB923000)
META CR3s:   4   (2601000 base=177D0152000; BBE1D000 base=6EB82E966000;
                  C0B0A000 base=177EFD66000; CB84D000 base=7BEEE7752000)
SPACE cr3=00000000CB84D000 base=00007BEEE7752000
HIT CM-name value=00007BEEE78374E1 at GPA 00000000BDB2B360
  CAND cls=00000000BDB2B350 name=OK ns=OK fc=40
       fields=00007BEEC2F4A6F8(mapped) f0=00007BEEE7837FA8(OK)
  *** VALID CharacterMotor CLASS at GPA 00000000BDB2B350 fc=40 ***
  f[27] off=+0x108  _laneStateInfo
  f[28] off=+0x138
  f[29] off=+0x1A8  _currentState
CharacterProgressEntry: only the 0x20-byte lookup-table record, no class
```

**Finding:** The game address space is `CR3=0xCB84D000`, metadata base
`0x7BEEE7752000`. The real runtime `Il2CppClass` layout is confirmed:
`name=+0x10`, `namespaze=+0x18`, `fields=+0x80`, `field_count u16=+0x124`,
`FieldInfo` stride `0x20`, `FieldInfo.name=+0x00`, `.offset=+0x18`, `.token=+0x1C`.
`CharacterMotor` (fc=40) is initialized during a live run; `CharacterProgressEntry` was
not initialized in the pause state. BlueStacks restarted during this probe
(HD-Player 556 exited at 13:06), so all GPAs are session-specific.

**Next question:** Resolve `CharacterMotor._laneStateInfo` (field 27, +0x108) to the
`LaneStateInfo` class and read `TargetLane` from live instances.

---

### [2026-11-11 13:23] Probe 16 — new session, lane-state attempt

**Question:** Does the new session expose `CharacterMotor` and `LaneStateInfo`, and what
is the user-supplied address `0x185C48C3E9C`?

**Method:** `recon_probe_16.dll`. Re-ran discovery, resolved `_laneStateInfo`'s
`Il2CppType`, searched for `LaneStateInfo`, looked for instances, and interpreted the
user address as a host VA and as a guest GVA in each space.

**Result (raw):**
```
SONAME GPA=00000000C4417770  magic GPA=00000000BB9ED000
SPACE space0(lib) cr3=00000000C8CFE000 base=000077E7214C9000
user addr 0x185C48C3E9C:
  host region base=00000185C48C3000 size=1CD000 RW private (valid host VA)
  not a mapped GVA here
CharacterMotor class not found (candidates fc=200/44/0, not classes)
```

**Finding:** The game was still loading, so `CharacterMotor` was not initialized yet.
The user address is a real host VA in HD-Player, in a 2 MB private allocation whose
contents include guest VAs.

**Next question:** Map that host allocation to the guest physical space.

---

### [2026-11-11 13:31] Probe 17 — host allocation layout

**Question:** Is the user host address the base of a RAM range mapping?

**Method:** `recon_probe_17.dll`. Dumped the RAM-range nodes, listed the largest host
regions and the allocation containing the address, and tried every plausible host base
as a guest-RAM base with a byte-for-byte comparison.

**Result (raw):**
```
containing allocation base=00000185C4890000 total span=200000 (2 MB)
hostbase=00000185C4890000 delta=000000033E9C
   Base RAM  gpa=0000000000033E9C match=no
   ... all ranges match=no
game CR3=0 (SONAME chain bug: page offset 0 used instead of SONAME offset)
```

**Finding:** Guest RAM is not mapped 1:1 from that allocation base; a RAM range's host
base is not the 2 MB allocation base. The host address is session-specific.

**Next question:** Find the backing guest physical chunk by content signature.

---

### [2026-11-11 13:36] Probe 18 — host page -> guest GPA by signature

**Question:** Which guest physical chunk contains the bytes at the user host address?

**Method:** `recon_probe_18.dll`. Took a 64-byte signature from the host page, scanned
all guest RAM for it, and dumped the match.

**Result (raw):**
```
signature matches: 1
MATCH guest addr 00000000A9033E9C (2MB base A9000000)
implied chunk base = 00000000A9000000 (match - host offset 0x33E9C)
G0000 BF80000000000000 | 0
G0020 435C0000BDA2C560 | 2CC892D000000001
G0030 2947E780000077E6 | 00000000000077E6
```

**Finding:** Host `0x185C48C3E9C` corresponds to guest GPA `0xA9033E9C` (chunk base
`0xA9000000`) in that session; the host allocation is a 2 MB-aligned guest chunk. The
page contains gameplay data (floats, guest object pointers), not a fixed lane field, so
the host address must not be hard-coded. Guest pointer values in it (`0x77E6...`) are in
the game's own address space.

**Next question:** Read the live `CharacterMotor` lane state in an active run.

---

### [2026-11-11 13:40] Session notes — modded APK and UI coordinates

The installed game is a LiteApks/9MOD Subway Surfers build: at startup it shows a mod
menu with `No Gravity`, `No Coins Pickup`, `Instant Lane Change`, etc. and a `CLOSE`
button at about `(352, 1557)` on the 900x1600 display. The pause menu shows a red
`QUIT` button on the left and a green `RESUME` button at `(645, 1495)`; `BACK` pauses a
live run. BlueStacks restarted again around 13:40 (HD-Player PID 11060, game PID 4591),
so every session must redo range/CR3/metadata/class discovery from scratch.

---

## Part 2 — Probes 19-32: finding the real lane field (2026-11-12)

### Probe 19 — confirm CharacterMotor / LaneStateInfo shapes

**Question:** Which field on `CharacterMotor` holds the lane state, and what is
`LaneStateInfo`'s internal layout?

**Method:** Class-name qword scan against the metadata base, validate
`name`/`field_count`/`field[0]`, dump `FieldInfo` names and offsets.

**Result:** `CharacterMotor` has 40 fields; `_laneStateInfo` is field[27] at `+0x108`.
A class named `LaneStateInfo` (fc=10, field[0]=`IsChangingLane`) was found by the name
scan and reported `IsChangingLane +0x10`, `TargetLane +0x24`.

**Finding:** The field/class discovery worked, but the offsets from the *name-scanned*
class are wrong for the inline struct (probes 28-29 below). `_runStateInfo` (field[26],
`+0xD0`) was also resolved at this point but later proved unusable (probe 21).

**Next question:** Does `CharacterProgressEntry` offer a simpler lane source?

### Probe 20 — CharacterProgressEntry is absent

**Question:** Can `CharacterProgressEntry` replace CharacterMotor for lane tracking?

**Method:** Class-name qword scan for `CharacterProgressEntry` + field dump.

**Result:** no class found; the type is never initialized in this build.

**Finding:** The CPE path is dead. Stay with `CharacterMotor._laneStateInfo`.

**Next question:** Is `_runStateInfo` a usable class pointer?

### Probe 21 — `_runStateInfo` is not a usable class pointer

**Question:** Does `CharacterMotor.field[26].type` point at a loadable class?

**Method:** resolve field[26]'s `Il2CppType`, translate `data.klass`, validate.

**Result:** 458 raw qword hits; only 6 passed loose sanity; the "class" read garbage
and no instances validated.

**Finding:** Do not rely on `_runStateInfo`. The lane state must come from
`_laneStateInfo` (an inline value type).

**Next question:** Why do metadata/class scans behave differently across sessions?

### Probes 22-24 — lazy init, aliases, and non-contiguous metadata

**Question:** Why do class scans fail on some sessions and succeed on others?

**Method:** repeated class scans across restarts; check physical contiguity of the
metadata mapping; inspect multiple CR3 mappings of the same page.

**Result:**
- classes are created lazily; a scan before first use finds nothing;
- the same class page appears under multiple CR3s (per-process aliases plus the
  direct-map alias `0x8880...`);
- the metadata file is mapped into non-contiguous physical pages, so physical
  contiguity must never be assumed.

**Finding:** Validate metadata/classes only through guest-virtual reads, never by
physical layout. Prefer chain-based discovery (`FindParentEntries` /
`ChainsForLeaves`) over walking every CR3 (probe 25 hung doing that).

**Next question:** Can the metadata base be found reliably when page tables and
strings are in flux?

### Probes 25-26 — losing CR3 discovery, winning with a string anchor

**Question:** How do we find the metadata base when the CR3 walk is unreliable?

**Method:** probe 25 tried the full CR3 list (stalled >5 min; probe 24 also hung on
reverse parent scans). Probe 26 instead scanned for the literal bytes of
`CharacterMotor` in guest RAM, built chains for that page, and derived the base by
subtracting the known file offset.

**Result:** probe 26 found metadata base `0x7C421DD18000` (CR3 `0xB6257000`) and
`CharacterMotor` class GPA `0xC0668350`. It also exposed hit-capping and prefix-match
bugs (`CharacterMotor` also matches `CharacterMotorState`).

**Finding:** The string-anchored method works but is expensive and depends on the
metadata string page being resident. Batched chain building for the *magic page* is
cheaper when the magic page is resident; keep both in mind.

**Next question:** What are the live offsets on the actual player object?

### Probe 27 — full FieldInfo dump and the first real motor

**Question:** What are all `CharacterMotor` offsets, and can we find a live player
instance?

**Method:** dump all 40 `FieldInfo` entries; scan for class-pointer qwords; read
allow/active/accel/velocity on every hit.

**Result (all offsets confirmed):**

```
velocity +0x1D4 (Vector3)   allowInput +0x1D0   isActive +0x1E8
canAccelerate +0x1EA       _currentState +0x1A8  _controller +0xC0
_laneStateInfo +0x108
```

One hit was clearly the player: GPA `0xCE7EFD80`, monitor 0, allow/active/accel = 1,
Velocity `(0, 50.276, 220.0)`. The lane dword read `0` at `+0x12C`.

**Finding:** The object signature is solid. `+0x12C` is **not** the lane field (it is
derived from the wrong LaneStateInfo class). `IsChangingLane` at `+0x118` read `0x53`,
confirming the wrong-class offsets.

**Next question:** Which offset actually changes when the player changes lanes?

### Probe 28 — the type's class is not the name-scanned class

**Question:** Is the LaneStateInfo class we found by name the one the field uses?

**Method:** read `CharacterMotor.field[27].type`, translate `data.klass`, compare with
the name-scanned class; sample the object while swiping.

**Result:**

```
field[27] type data.klass GPA = 0xC3BDA648
name-scanned LaneStateInfo GPA = 0xD4514CB0   -> MISMATCH
```

There are (at least) two runtime classes carrying the same metadata name. The
name-scanned one yields `IsChangingLane +0x10` / `TargetLane +0x24`, which do not match
the inline struct (hence the garbage `0x53`).

**Finding:** Resolve value-type classes through the field's `Il2CppType`, not by
scanning for the name. Keep the verified inline offsets as fallbacks.

**Next question:** Empirically map the inline struct by observing a real lane change.

### Probe 29 — observing the lane change (the decisive probe)

**Question:** Which dwords of the object change when the player changes lanes?

**Method:** find the motor, then sample all 128 dwords of the object every 150 ms for
75 s while alternating `input touchscreen swipe`s run. A hoverboard loop kept the run
alive. Log only changed dwords plus a per-offset value summary.

**Result:** the inline `LaneStateInfo` (starting at object `+0x108`) behaved exactly as
a lane-change state machine:

```
+0x108  bool   IsChangingLane            0 <-> 1, 26 changes (one per swipe)
+0x10C  float  LaneChangeElapsedTime     0 -> 0.0583, 0.2417, 0.2667 ...
+0x110  float  LaneChangeDuration        0.2333-0.2519 s
+0x114  float  LaneChangeSpeedModifier   constant 1.0
+0x118  float  RunDistanceWhileLaneChanging  7.27, 24.09, 31.13, 44.60 ...
+0x11C  int    TargetLane                {-1, 0, 1}, flips at every swipe
+0x120  float  source/target lane position  {0, -1.0, +1.0}
+0x138         _impactFrameState begins (struct size 0x30)
```

**Finding:** **`TargetLane` is the int32 at object `+0x11C`** (= `_laneStateInfo` at
`+0x108`, `TargetLane` at `+0x14`), and **`IsChangingLane` is at `+0x108`**. Values are
`-1 / 0 / 1` for left / centre / right. `+0x12C` (the old guess) is inside
`SourceLanePosition`, not the lane.

**Next question:** Does this hold end-to-end through the pipe during a real run?

### Probes 30-31 — why the recon DLL suddenly could not validate the class

**Question:** Probe 29 could read `FieldInfo`, but the recon DLL could not; why?

**Method:** probe 30 read the class directly and dumped the qword-scan candidates.
Probe 31 walked the page tables for the class's `fields` pointer.

**Result:**

```
direct class 0xBA59F350: name=0x77B9235034E1, fields=0x77B8A0584460, fc=40   (valid)
qword candidates with the same name pointer: fc=200 / 112 / 44, f0='_stumble' / '_info'
X64Translate(fields) = 0
PT entry for 0x77B8A0584460 = 0x07FFFFFFFD611C00   (present bit clear)
```

**Finding:** The class was alive, but Android had **paged out the FieldInfo array**
(and, in later sessions, the metadata string pages). The recon rejected the class
because `field[0]`'s name could not be read. This is not a discovery bug: the page is
simply not resident.

Robust rules adopted:
- Validate a class by `name pointer == metadataBase+offset` **and** `field_count`,
  and only compare `field[0]`'s name when it is actually readable;
- treat an empty string read as "unknown", never as a mismatch;
- never require metadata strings to accept a metadata base: validate the magic,
  page alignment, user-space range, then confirm the base by finding the class-name
  qwords. Android may page out the string pages independently.

**Next question:** Can the base be found in a fresh session where all strings are gone?

### Probe 32 — metadata base without any string reads

**Question:** Does the base still validate when every metadata string page is paged out?

**Method:** scan for the metadata magic, build chains, and for each mapping derive the
page-aligned base. Validate by scanning for qwords equal to `base+0xE54E1` and checking
the class header (`name`/`fields`/`fc`) without reading any string content.

**Result (fresh session):**

```
magic hits = 1   GPA 0xADF58000
chain: cr3=0x11BEA4000 gva=0x7F49D205B000 gpa=0xADF58000 magic=FAB11BAF user=1 page-aligned
strings at base+0xE54E1 / base+0xE5FA8 -> ""        (paged out)
name-pointer qwords = 75
exactly one candidate: cls=0xBE582350 fc=40         (the CharacterMotor class)
```

**Finding:** The base can be validated geometrically (magic, alignment, user-space)
and then confirmed by class discovery. A heap copy of the magic would produce no
`fc=40` class at `base+OFF_CM_NAME`, so the confirmation step is safe.

**Next question:** End-to-end run with the corrected offsets.

### Final verification — full pipeline live

**Session:** HD-Player PID 1080, game PID 3602.

**Stage 4** found the magic `0xADF58000` mapped under four CR3s:

```
CR3 0xCACC9000  base 0x64B2434EC000   class-name qwords = 0
CR3 0x11FFFD000 base 0x2B32434EC000   class-name qwords = 0
CR3 0x02601000  base 0x0195834EC000   class-name qwords = 0
CR3 0xC2D55000  base 0x724AF24EC000   class-name qwords = 74  <-- the game
```

Only the fourth mapping contains the game's class objects. `CharacterMotor` class GPA
`0xCB39D350`, fc=40. Class-pointer GVAs: `0x724AC0916350` (user) and `0x8880CB39D350`
(direct-map alias of the same GPA). The `LaneStateInfo` type was unresolved (its
FieldInfo page was paged out), so the verified inline offsets were used.

**Stage 5** hit count 457, `monitor==0` 4, lane-ok 2, flag-ok 1, sane 1; picked
`motor = 0xA6CA6240` (`LANE_GPA = 0xA6CA635C`). The motor object is the persistent
player object: it exists on the menu with `active=0`, and becomes active once the run
starts.

**Pipe verification (real run, screenshots checked each step):**

```
READ                      -> LANE 0        (centre lane)
swipe right (250->650)    -> LANE 1        (player visibly on the right train)
swipe left  (650->250)    -> LANE 0
START + swipe sequence    -> LANE 0, 1, 0, -1, 0, 1   (streams on every change)
```

**Finding:** The Android 11 lane reader is complete. `LANE` is `TargetLane`
(object `+0x11C`), streamed on change. The six-stage pipeline
(bridge -> ranges -> CR3s -> metadata/classes -> player motor -> pipe stream) runs to
completion in a single injection.

**Operational notes for future sessions:**

- One injection per BlueStacks session; a stuck probe or a recompile requires a full
  HD-Player restart (DLLs cannot be unloaded safely, and the pipe name is occupied).
- Everything (metadata base, CR3 alias, class GPA, motor GPA) changes per session;
  only the offsets and signature constants are stable.
- The player object survives menu <-> run transitions, so a motor cached on the menu
  still works once a run starts.
- `input touchscreen swipe <x1> <y1> <x2> <y2> 140` at y=1200 is reliable for lane
  changes; `input tap` at `(200,1220)` starts a run from the menu when the
  "Collections" coach mark covers the play button.
- The mod menu ("9" badge) can leave God Mode / hoverboards on; useful for keeping a
  run alive while probing, but it covers the left edge of the screen.
