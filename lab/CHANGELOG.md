# Autonomous Subway Surfers Bot — Changelog

All versions of `recon.dll` and companion tooling.
Format: version · what broke · what was fixed · what was learned.

---

## v12 — Persistent pipe server + VS control plane
**Files:** `recon_v12.cpp`, `SubwayBot.cs`

### Problem
Every iteration of bot logic required recompiling and reinjecting `recon.dll`.
Unloading the DLL mid-session consistently crashed BlueStacks by corrupting
VBox VMM state during `DLL_PROCESS_DETACH`.

### Changes
- **`BotLoop()` removed from the DLL.** Bot logic now lives entirely in `SubwayBot.cs`.
- **Named pipe server added** (`\\.\pipe\recon`). DLL exposes a simple ASCII
  line protocol: `PING`, `SET_GPA`, `READ`, `HVA_BASE`, `START`, `STOP`.
- **`DLL_PROCESS_DETACH` explicitly ignored.** FreeLibrary on this DLL is
  intentionally unsupported and will crash BlueStacks. Inject once per session.
- **ELF scan floor lowered** from `0x10000000` to `0x1000000`. Previous floor
  missed `libil2cpp.so` headers that land below the 256 MB mark.
- **`SubwayBot.cs`** — new VS Console App project. Connects to the pipe,
  receives `LANE` stream, runs `BotReact()`. Restart it freely without
  touching BlueStacks. Includes console commands for live GPA updates.
- **Auto GPA computation** in SubwayBot: paste the CE address at the console
  and it subtracts `HVA_BASE` for you.

### Workflow now
```
BlueStacks boot → inject recon.dll once → never touch it again
                                        ↓
                              SubwayBot.exe (VS) connects via pipe
                              iterate bot logic → rebuild → re-run SubwayBot only
```

---

## v11 — ARM64 page table walk for scattered ELF pages
**File:** `recon.cpp` (shipped as v11 in log output)

### Problem (from v10)
`libil2cpp.so` is 81 MB. Its physical pages are **scattered** throughout guest
RAM — not contiguous. Finding the ELF header page at a GPA and then reading
`PT_DYNAMIC` at `elfBase + dyn_file_offset` read garbage because those file
pages were at entirely different GPAs.

### Fix
Full ARM64 3-level page table walk (GVA ↔ GPA translation).

| Step | Function | Purpose |
|------|----------|---------|
| 3a | `FindLibIl2CppBase()` | ELF header GPA scan, parse phdrs, get `PT_DYNAMIC p_vaddr` |
| 3b | `FindTTBR0()` | Reverse PTE scan: find PTE whose OA == ELF header GPA, walk up PTE→PMD→PGD = TTBR0 |
| 3c | `GvaToGpa()` | Standard 3-level ARM64 walk: PGD→PMD→PTE→PA |
| 4  | `ReadIl2CppExports()` | Read PT_DYNAMIC via GVA translation, walk dynsym/strtab page-by-page |

ARM64 VA layout used (Android default, 39-bit):
- `VA[38:30]` → PGD index
- `VA[29:21]` → PMD index
- `VA[20:12]` → PTE index

### Also added
- `DIRECT_LANE_GPA` compile-time bypass for use while self-discovery is in progress.
- `GvaRead()` handles page boundaries: translates each 4KB page independently.
- 2 MB block mapping handled at PMD level.

### Session results
- VBox bridge: ✅ working
- Range map: ✅ single flat range, 3584 MB
- ELF scan: ⚠️ found 1 candidate (`0xCD31F000`) but `dyn_offset=0xEE0` — not libil2cpp
  (too small; libil2cpp threshold is > 64 MB). Scan floor too high (`0x10000000`).
- Stages 3b–6: did not run (gated on ELF found)
- Bypass path: used successfully once GPA was computed manually

---

## v10 — Contiguous ELF read attempt (broken)

### Problem
Attempted to read `PT_DYNAMIC` by: find ELF header GPA → add `dyn_file_offset`
→ read from that GPA. Assumed `.so` pages were laid out contiguously in physical
RAM. They are not. Physical pages of a mapped shared library are wherever the
kernel placed them. Result: garbage reads from unrelated physical pages.

### Lesson
Never assume virtual-address-contiguous data is physically contiguous.
Must use page table walk to translate every GVA → GPA individually.

---

## v9 and earlier — VBox bridge development

### Achievements by this point
- **Seven BstkVMM.dll exports resolved and confirmed:**

| Export | Purpose |
|--------|---------|
| `VMR3GetVM(pUVM)` | PUVM → PVM |
| `VMR3GetUVM(pVM)` | PVM → PUVM (round-trip verify) |
| `VMR3GetState` | VM lifecycle state |
| `PGMR3PhysGetRamRangeCount(pVM)` | guest RAM range count |
| `PGMR3PhysGetRange` | range GPA + HVA + size — **abandoned** |
| `PGMPhysSimpleReadGCPhys(pVM, dst, gpa, cb)` | ✅ read guest RAM |
| `PGMPhysSimpleWriteGCPhys(pVM, gpa, src, cb)` | write guest RAM |

- **UVM/PVM handle scan:** page-aligned committed non-image memory scan for
  magic `0x19700823` → `pUVM`. `pVM` at `pUVM+8`. Round-trip verified.
  Stable across injections within a session.

- **GPA read confirmed:** `PGMPhysSimpleReadGCPhys` at GPA `0x0` returns
  `53 FF 00 F0` — ARM64 `ret` trampoline filler. Correct guest RAM content.

- **`PGMR3PhysGetRange` abandoned:** throws on every index despite correct
  signature. Disasm shows internal lock acquisition before the list dereference
  — misfires outside normal VBox call context. Prefaulting `pVM` doesn't fix it.

- **Range list direct walk:** disasm of `PGMR3PhysGetRange` at `+0x118` revealed
  `mov rcx, [rbx+0x1010]` where `rbx=pVM` — that's `pRamRangesXR3`, the linked
  list head. Walked it directly. BlueStacks uses a single flat range:
  ```
  GCPhysStart = 0x00000000
  GCPhysEnd   = 0xE0000000
  Size        = 3584 MB
  ```

- **GPA volatility understood:** lane GPA lives inside a Unity heap object that
  relayouts on every game launch. Must be re-discovered or re-pinned each session.

---

## CE / GPA session log

| Session | CE_HVA | HVA_BASE | GPA | Result |
|---------|--------|----------|-----|--------|
| 1 | `0x19343A3DE9C` | `0x192947184F0` | `0xAF32599C` | read `0x4D617469` ("Mati") — wrong address |
| 1 | `0x19343A3DE9C` | `0x192947184F0` | `0xAF3259AC` | `-16769532` — HVA_BASE stale (new session) |
| 2 (crash+restart) | `0x180C439C11C` | `0x18025E584F0` | `0x9E543C2C` | pending |
| 3 (crash+restart) | `0x1F2BDE0A11C` | `0x1F27C3784F0` | `0x41A91C2C` | SET_GPA silently dropped — mid-stream command bug in pipe server (fixed in v12 patch) |
| 4 (crash+restart) | `0x22B6B8FAC5C` | `0x22B22C684F0` | `0x48C9276C` | pending — first session with fixed pipe server |

**GPA formula:** `GPA = CE_HVA - HVA_BASE`
where `HVA_BASE` = `HC` field of `range[0]` in Stage 2 log (the flat 3584 MB range).

**Common failure modes:**
- Reading ASCII garbage → off by a few bytes, re-scan CE with 4-byte int filter
- Reading large negative / random int → HVA_BASE is from a previous session; restart BlueStacks or re-inject to get fresh Stage 2 log
- CE address in wrong process → ensure CE is attached to `HD-Player.exe`, not a child
- SET_GPA sent mid-stream with no response → pipe server only handled STOP in streaming loop (fixed in v12 patch)

---

## Stage 3a/3b milestone — session 4

**libil2cpp.so found for the first time** at `GPA=0x9D6E4000`, `dyn_offset=73.7 MB` ✓

Three candidates this scan:
```
GPA=0x9A8B6000  phnum=10  dyn_offset=0x24A88   (0.1 MB)  — rejected, too small
GPA=0x9AE7C000  phnum=5   dyn_offset=0xEE0     (0.0 MB)  — rejected, too small
GPA=0x9D6E4000  phnum=10  dyn_offset=0x49AAD70 (73.7 MB) — IDENTIFIED libil2cpp.so ✓
```

Lowering the ELF scan floor from `0x10000000` to `0x1000000` in v12 was what made this possible — previous sessions the header page landed below the old floor.

**Stage 3b: PTE scan — no candidates found**

Scanned all 3584 MB of guest RAM for a PTE with `OA == 0x9D6E4000`. Zero hits.

Root cause: the ELF header page (`0x9D6E4000`) is a **physical page that is not currently mapped** in any live process page table. The kernel loaded `libil2cpp.so`, read the ELF header to set up the mapping, then the header page was reclaimed / evicted. The `.text` and `.data` segments are still mapped and in use — just not the header page itself.

**Next fix options (in order of preference):**

1. **Don't scan for the header page.** Instead, find the `.text` segment — it's always resident while the game runs. Strategy: find any export RVA we know (e.g. `il2cpp_domain_get`, known from offline metadata), scan guest RAM for the ARM64 function prologue at that RVA offset from each candidate base. The base that matches is `libil2cpp_load_base`.

2. **Scan for SONAME string.** The string `"libil2cpp.so"` lives in `.dynstr`, which is in the resident `.rodata` segment. Scan for it, then walk back to find the load base.

3. **Scan for a unique IL2CPP global pointer.** `g_Il2CppInteropData` or similar — a known-pattern pointer that only exists in libil2cpp's data segment. Offset from it to load base is stable per build.

Option 2 is fastest to implement. Option 1 is most robust long-term.

---

## IL2CPP offline analysis

**APK:** `com.kiloo.subwaysurf`, pulled via ADB at 31.8 MB/s, 282 MB.

**Extracted:**
- `libil2cpp.so` — 81,168,448 bytes, ARM64 ELF
- `global-metadata.dat` — 16,382,824 bytes, metadata v31

**Custom extractor** (`extract_offsets.py`) written — no Il2CppDumper needed.

**Confirmed:**
- 20,393 types, 124,001 methods, 117,148 fields
- `CharacterInputController` at typedef index 199, namespace `SYBO.RunnerCore.Character`

**Bug history in extractor:**
- v1/v2: `parentIdx` treated as a typedef index — out of range, chain walk failed
- v3: fixed with proper `typeIndex→typedef` resolution via `pair[20]`
- v3 also: brute-force scan of all 117,148 fields for any name containing `lane` or `Lane`

**Status:** v3 pending run. Field offset unknown until it completes.

---

## Architecture overview

```
Unity IL2CPP ARM64 (Android, com.kiloo.subwaysurf)
        ↓
  VirtualBox guest physical RAM (3584 MB, one flat range)
        ↓
  BstkVMM.dll — patched VBox VMM inside HD-Player.exe
        ↓
  recon.dll (injected, resident) — VBox bridge + pipe server
        ↓  \\.\pipe\recon
  SubwayBot.exe (VS project) — bot logic, GPA management, console UI
```