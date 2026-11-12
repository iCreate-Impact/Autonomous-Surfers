# BlueStacks Android 11 — Guest Memory Access Framework
### Complete Technical Reference for Game-Agnostic Memory Reading
#### Based on `recon_android11.dll` — GCC 15.2.0 / MinGW-w64 / MSYS2 — Built 2026-11-12

---

## Overview

This document describes a complete, working framework for reading guest Android
physical and virtual memory from within `HD-Player.exe` on **BlueStacks 5,
Android 11**, using the VirtualBox VMM bridge that BlueStacks exposes internally.

The framework was developed through 32 live probes against a running BlueStacks
Android 11 instance. Everything in this document was measured from a live system,
not inferred from documentation.

The core machinery — Stages 1 through 3b — is **fully game-agnostic**. It works
for any process running in the Android guest. The upper stages (4 onwards) are
where game-specific logic lives, and this document explains exactly how to
adapt them for any target.

---

## Table of Contents

1. [Environment and Prerequisites](#1-environment-and-prerequisites)
2. [Architecture Overview](#2-architecture-overview)
3. [Stage 1 — VirtualBox VMM Bridge](#3-stage-1--virtualbox-vmm-bridge)
4. [Stage 2 — Guest RAM Range Map](#4-stage-2--guest-ram-range-map)
5. [Stage 3 — Game Address Space Discovery](#5-stage-3--game-address-space-discovery)
6. [Stage 4 — IL2CPP Class Discovery (Unity Games)](#6-stage-4--il2cpp-class-discovery-unity-games)
7. [Stage 5 — Instance and Field Reading](#7-stage-5--instance-and-field-reading)
8. [Stage 6 — Named Pipe Output](#8-stage-6--named-pipe-output)
9. [Adapting for a New Game](#9-adapting-for-a-new-game)
10. [Non-Unity Games](#10-non-unity-games)
11. [Known Pitfalls](#11-known-pitfalls)
12. [Constants Reference](#12-constants-reference)
13. [What Changed from Android 9](#13-what-changed-from-android-9)

---

## 1. Environment and Prerequisites

| Item | Detail |
|------|--------|
| Host OS | Windows 10/11 x64 |
| Emulator | BlueStacks 5 |
| Guest Android | Android 11 |
| Guest kernel | Linux 4.19 x86_64 |
| Main process | `HD-Player.exe` (x64) |
| VMM module | `BstkVMM.dll` (VirtualBox VMM, v2.1.24.117012) |
| Compiler | GCC 15.2.0, MinGW-w64, MSYS2 |
| Output | `recon_android11.dll` — injected once per BlueStacks session |

**What you need:**
- A working DLL injector targeting `HD-Player.exe`
- The game already running in BlueStacks before injection
- For Unity games: `Il2CppDumper` output from the target APK
- The named pipe client (`SubwayBot.cs` or equivalent) for consuming output

**What you do NOT need:**
- A kernel driver
- Admin privileges beyond what injection requires
- Any modification to BlueStacks itself
- Any modification to the game APK

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    HD-Player.exe (host)                   │
│                                                           │
│  ┌─────────────────┐     ┌──────────────────────────┐    │
│  │  BstkVMM.dll    │     │   recon_android11.dll    │    │
│  │  (VBox VMM)     │◄────│   (injected)             │    │
│  │                 │     │                           │    │
│  │  VMR3GetUVM     │     │  Stage 1: VBox bridge     │    │
│  │  VMR3GetVM      │     │  Stage 2: RAM range map   │    │
│  │  PGMPhysRead    │     │  Stage 3: CR3 discovery   │    │
│  │  PGMPhysWrite   │     │  Stage 4: class scan      │    │
│  └─────────────────┘     │  Stage 5: instance read   │    │
│           │               │  Stage 6: pipe server     │    │
│           │               └──────────┬───────────────┘    │
│           ▼                          │                     │
│  ┌─────────────────┐                 │ \\.\pipe\recon      │
│  │  Guest Physical │                 │                     │
│  │  Memory (GPA)   │       ┌─────────▼──────────┐         │
│  │                 │       │  SubwayBot.exe /    │         │
│  │  Base RAM       │       │  any pipe client    │         │
│  │  0x0–0xDFFFFF   │       │                     │         │
│  │                 │       │  LANE -1/0/1        │         │
│  │  Above-4GB RAM  │       └────────────────────-┘         │
│  │  0x100000000–   │                                       │
│  │  0x11FFFFFFF    │                                       │
│  └─────────────────┘                                       │
└──────────────────────────────────────────────────────────-┘
```

The key insight: `BstkVMM.dll` is loaded inside `HD-Player.exe` and exports
VirtualBox VMM functions. These give direct read/write access to the entire
guest physical address space from the host process, with no kernel driver
and no hypervisor escape required.

---

## 3. Stage 1 — VirtualBox VMM Bridge

### What it does

Locates `BstkVMM.dll` in `HD-Player.exe`'s module list, resolves five exports,
and obtains the `pVM` and `pUVM` pointers that everything else depends on.

### Exports resolved

```cpp
VMR3GetUVM            // returns pUVM from the running VM instance
VMR3GetVM             // returns pVM from pUVM
PGMR3PhysGetRamRangeCount  // returns number of guest RAM ranges
PGMPhysSimpleReadGCPhys    // read N bytes from guest physical address
PGMPhysSimpleWriteGCPhys   // write N bytes to guest physical address
```

### Finding pVM

`pVM` is not exported directly. It's located by scanning host virtual memory
for the VBox magic value `0x19700823`:

```cpp
// scan host VA space for the UVM struct
for (addr = 0x10000; addr < 0x7FFFFFFFFFFF; addr += page) {
    if (*(uint32_t*)addr == 0x19700823) {
        pUVM = (void*)addr;
        pVM  = VMR3GetVM(pUVM);
        break;
    }
}
```

### Read/write API

```cpp
// Read cb bytes from guest physical address gpa into buf
int rc = PGMPhysSimpleReadGCPhys(pVM, buf, gpa, cb);
// rc == 0 on success, negative on failure

// Write cb bytes from buf to guest physical address gpa
int rc = PGMPhysSimpleWriteGCPhys(pVM, gpa, buf, cb);
```

### Critical: chunk your reads

`PGMPhysSimpleReadGCPhys` fails if any page in the requested range is
not present (demand-paged, swapped, or unmapped). **Never read more than
64 KB in a single call.** For large ranges, use 64 KB chunks with 4 KB
fallback for chunks that fail:

```cpp
bool GuestRead(uint64_t gpa, void* buf, size_t cb) {
    // try 64KB at a time; fall back to 4KB pages for failing chunks
    for (size_t off = 0; off < cb; off += 0x10000) {
        size_t chunk = min(cb - off, 0x10000);
        int rc = PGMPhysSimpleReadGCPhys(pVM, (uint8_t*)buf+off, gpa+off, chunk);
        if (rc != 0) {
            // retry page by page
            for (size_t p = 0; p < chunk; p += 0x1000) {
                size_t pg = min(chunk-p, 0x1000);
                rc = PGMPhysSimpleReadGCPhys(pVM, (uint8_t*)buf+off+p, gpa+off+p, pg);
                if (rc != 0) memset((uint8_t*)buf+off+p, 0, pg);
            }
        }
    }
    return true;
}
```

---

## 4. Stage 2 — Guest RAM Range Map

### What it does

Walks the linked list of guest RAM ranges inside `pVM` to build a map of
all physically-backed guest memory.

### The range linked list

Located at `pVM + 0x1010`. This is a linked list of `PGM_RAM_RANGE` nodes.

**Android 11 node layout (BstkVMM 2.1.24):**

```
+0x00  uint64  GCPhysStart    guest physical start address (inclusive)
+0x08  uint64  cb             size in bytes
+0x10  ptr     pNextR3        pointer to next node (NULL = end of list)
+0x18  ...     (internal)
+0x24  uint32  flags          bit 22 = IsRom
+0x28  uint64  GCPhysLast     guest physical end address (inclusive)
+0x40  ptr     pszDesc        pointer to ASCII description string
```

> **Android 9 difference:** `pNextR3` was at `+0x30`, `GCPhysLast` was read
> from `+0x08`. Both are wrong for Android 11.

### Walking the list

```cpp
struct RamRange { uint64_t start, end; };
std::vector<RamRange> ranges;

uint64_t nodeGpa;
GuestRead(pVM_gpa + 0x1010, &nodeGpa, 8);

while (nodeGpa != 0) {
    uint64_t gcStart, gcLast, next;
    GuestRead(nodeGpa + 0x00, &gcStart, 8);
    GuestRead(nodeGpa + 0x28, &gcLast,  8);
    GuestRead(nodeGpa + 0x10, &next,    8);
    
    // only include general-purpose RAM (cb >= 64 MB, non-ROM)
    uint64_t cb = gcLast - gcStart + 1;
    if (cb >= 0x4000000) ranges.push_back({gcStart, gcLast});
    
    nodeGpa = next;
}
```

### Android 11 RAM layout

After walking all 20 nodes, only two are general-purpose RAM:

| Index | GC Start | GC End | Size | Description |
|-------|----------|--------|------|-------------|
| 0 | `0x00000000` | `0xDFFFFFFF` | 3584 MB | Base RAM |
| 19 | `0x100000000` | `0x11FFFFFFF` | 512 MB | Above 4GB Base RAM |

**All scans must cover both ranges.** The other 18 entries are MMIO/device
windows (VRam, VMMDev, audio buffers, camera, BIOS, APIC, etc.) and should
be skipped for memory scanning.

The `HVA_BASE` for the CE→GPA formula comes from range[0]'s host virtual
address, available via the node's internal `HCPhys` field.

---

## 5. Stage 3 — Game Address Space Discovery

This stage finds the game process's page table root (CR3) so that guest
virtual addresses (GVA) can be translated to guest physical addresses (GPA).

### Why this is necessary

The IL2CPP runtime stores pointers as guest virtual addresses. To follow
a pointer chain (class → fields → field names, etc.) you must translate
GVA → GPA at each step. That translation requires the game process's
page table root.

### The page table format

**Android 11 uses x86_64 4-level page tables, not ARM64.**

The guest kernel is `Linux 4.19 x86_64`. Page table walk:
```
CR3 → PML4[VA bits 47:39]
    → PDPT[VA bits 38:30]
    → PD  [VA bits 29:21]
    → PT  [VA bits 20:12]
    → physical page + offset[11:0]
```

PTE/PDE/PDPTE/PML4E format:
```
bit  0     Present (P)
bit  1     Read/Write (RW)
bit  2     User/Supervisor (US)  — 1 = user space
bit  7     Page Size (PS)        — 1 = 2 MB large page (in PD level)
bits 12:51 Physical address >> 12
bit 63     No-Execute (NX)
```

Physical address mask: `entry & 0x000FFFFFFFFFF000`

**The page tables themselves live in the Above 4GB RAM range
(`0x100000000–0x11FFFFFFF`).** This is why Android 9 code found nothing —
it never scanned above `0xE0000000`.

### Finding CR3

The anchor is the `"libil2cpp.so"` SONAME string, which stays resident
in physical memory throughout the game session (unlike the ELF header
page, which gets evicted after ~1 hour).

**Step 1 — Find the SONAME string**

Scan all RAM for the null-terminated ASCII string `"libil2cpp.so"`.
It appears in the `.dynstr` section of libil2cpp.so's mapping. Record
all GPA locations.

```cpp
// scan both RAM ranges for the 13-byte sequence
const char target[] = "libil2cpp.so";
for (auto& range : g_ramRanges) {
    for (uint64_t gpa = range.start; gpa < range.end; gpa += 0x1000) {
        uint8_t page[0x1000];
        if (!GuestRead(gpa, page, 0x1000)) continue;
        // search page for the string...
    }
}
```

**Step 2 — Find the PTE mapping that page**

Scan the Above 4GB range for x86_64 PTEs whose output address (OA) equals
the page containing the SONAME string:

```cpp
uint64_t sonamePageGpa = sonameGpa & ~0xFFFULL;

for (uint64_t gpa = 0x100000000; gpa < 0x120000000; gpa += 8) {
    uint64_t entry;
    GuestRead(gpa, &entry, 8);
    
    uint64_t oa = entry & 0x000FFFFFFFFFF000ULL;
    if ((entry & 1) && oa == sonamePageGpa) {
        // found a 4KB PTE mapping the SONAME page
        pteGpa = gpa;
    }
}
```

**Step 3 — Walk up to CR3**

```cpp
// PTE is at index (VA >> 12) & 0x1FF in its PT page
uint64_t ptPageGpa  = pteGpa & ~0xFFFULL;

// find PDE whose OA == ptPageGpa
// find PDPTE whose OA == pdPageGpa
// find PML4E whose OA == pdptPageGpa
// the page containing the PML4E is CR3

uint64_t cr3 = pml4PageGpa;
```

**Step 4 — Handle multiple aliases**

A physical page can be mapped by multiple CR3s simultaneously:
- the game process
- the kernel direct map
- KPTI shadow page tables
- other processes that loaded libil2cpp.so

Identify the game CR3 by:
1. The SONAME GVA should be a low user-space address (`< 0x0001000000000000`)
2. The same CR3 should also map the global-metadata.dat magic bytes
   (`0xFAB11BAF` at the start of the metadata file)
3. Under this CR3, IL2CPP class objects should be found (Stage 4 confirms)

### GVA → GPA translation

```cpp
uint64_t X64Translate(uint64_t cr3, uint64_t gva) {
    uint64_t pml4e_gpa = cr3 + ((gva >> 39) & 0x1FF) * 8;
    uint64_t pml4e; GuestRead(pml4e_gpa, &pml4e, 8);
    if (!(pml4e & 1)) return 0;  // not present

    uint64_t pdpte_gpa = (pml4e & PHYS_MASK) + ((gva >> 30) & 0x1FF) * 8;
    uint64_t pdpte; GuestRead(pdpte_gpa, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1<<7)) return (pdpte & PHYS_MASK) + (gva & 0x3FFFFFFF); // 1GB

    uint64_t pde_gpa = (pdpte & PHYS_MASK) + ((gva >> 21) & 0x1FF) * 8;
    uint64_t pde; GuestRead(pde_gpa, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & (1<<7)) return (pde & PHYS_MASK) + (gva & 0x1FFFFF);  // 2MB

    uint64_t pte_gpa = (pde & PHYS_MASK) + ((gva >> 12) & 0x1FF) * 8;
    uint64_t pte; GuestRead(pte_gpa, &pte, 8);
    if (!(pte & 1)) return 0;  // see note on swapped PTEs below

    return (pte & PHYS_MASK) + (gva & 0xFFF);
}
```

> **Swapped PTE note:** A PTE with bit 0 clear but a non-zero value is a
> valid page that has been swapped out or demand-paged. The kernel knows
> how to restore it; from the host you cannot. The workaround is to not
> rely on GVA translation for fields whose pages may be paged out — use
> direct GPA reads based on measured struct offsets instead.

---

## 6. Stage 4 — IL2CPP Class Discovery (Unity Games)

This stage locates the target class object in guest physical memory.
It applies to any game built with Unity using IL2CPP (which is the
majority of serious mobile games).

### IL2CPP runtime layout (Android 11)

**`Il2CppClass` struct (confirmed from live session):**

```
+0x00  ptr   image           Il2CppImage*
+0x10  ptr   name            char* (class name string)
+0x18  ptr   namespaze       char* (namespace string)
+0x28  ptr   parent          Il2CppClass*
+0x30  ptr   element_class   Il2CppClass*
+0x80  ptr   fields          FieldInfo*  (array of field descriptors)
+0x88  ptr   methods         MethodInfo**
+0x90  ptr   interfaces      Il2CppClass**
+0x124 u16   field_count     number of fields
+0x128 u16   method_count
```

**`FieldInfo` struct (stride = `0x20`):**

```
+0x00  ptr   name    char* (field name string)
+0x08  ptr   type    Il2CppType*
+0x10  ptr   parent  Il2CppClass*
+0x18  i32   offset  byte offset within instance object
+0x1C  u32   token
```

> **Android 9 difference:** `FieldInfo` stride was `0x18`. On Android 11
> it is `0x20`. Using the wrong stride produces garbage field offsets.

### Finding the metadata base

The global metadata file (`global-metadata.dat`) is mapped into every process
that uses IL2CPP. It starts with the magic value `0xFAB11BAF`.

Scan both RAM ranges for this 4-byte magic at page-aligned addresses.
Verify it is in the game's address space (confirmed by CR3 from Stage 3).
The GVA of the metadata file is the metadata base — all string offsets
in the metadata are relative to this base.

```cpp
// scan for metadata magic
for (auto& range : g_ramRanges) {
    for (uint64_t gpa = range.start; gpa < range.end; gpa += 0x1000) {
        uint32_t magic;
        if (!GuestRead(gpa, &magic, 4)) continue;
        if (magic == 0xFAB11BAF) {
            // verify it's page-aligned and maps into our CR3
            uint64_t chains = GetPTEChains(gpa);
            if (chains > 0) metadataGpa = gpa;
        }
    }
}
```

**Resilience note:** Metadata string pages may be paged out between sessions.
Accept the metadata base on magic + page alignment + user-space range alone.
Confirm the base is correct through class discovery (Stage 4), not through
string reads. An empty string read means "unknown", not "mismatch".

### Scanning for a class by name

```cpp
// 1. Find the class name string in metadata
//    e.g. "CharacterMotor" at some GPA inside the metadata mapping
uint64_t nameGpa = FindStringInRam("CharacterMotor");
uint64_t nameGva = GpaToGva(cr3, nameGpa);  // reverse translate

// 2. Scan all RAM for a qword equal to nameGva
//    candidate is at the found address - 0x10 (the name field is +0x10)
for (auto& range : g_ramRanges) {
    for (uint64_t gpa = range.start; gpa < range.end; gpa += 8) {
        uint64_t val;
        GuestRead(gpa, &val, 8);
        if (val == nameGva) {
            uint64_t classGpa = gpa - 0x10;
            // validate: check field_count, translate fields pointer, etc.
        }
    }
}

// 3. Validate the candidate
uint16_t fc;
GuestRead(classGpa + 0x124, &fc, 2);
if (fc != expectedFieldCount) continue;

// 4. Optionally validate field[0].name if the fields page is present
uint64_t fieldsGva;
GuestRead(classGpa + 0x80, &fieldsGva, 8);
uint64_t fieldsGpa = X64Translate(cr3, fieldsGva);
if (fieldsGpa != 0) {
    uint64_t f0nameGva;
    GuestRead(fieldsGpa, &f0nameGva, 8);  // FieldInfo[0].name
    // translate and read the string to verify
}
```

---

## 7. Stage 5 — Instance and Field Reading

### Finding live instances

A Unity object instance's first field is its `klass` pointer, which points
to the `Il2CppClass` for that object's type.

To find all live instances of a class:

```cpp
uint64_t classGpa = ...; // from Stage 4

// scan all RAM for objects whose klass pointer matches
for (auto& range : g_ramRanges) {
    for (uint64_t gpa = range.start; gpa < range.end; gpa += 0x10) {
        uint64_t klass;
        GuestRead(gpa, &klass, 8);
        uint64_t klassGpa = X64Translate(cr3, klass);
        if (klassGpa == classGpa) {
            // gpa is the start of a live instance
        }
    }
}
```

For game objects, additional validation helps filter false positives:
- the instance should be in a plausible heap range
- other known fields should have sane values (floats in range, booleans 0/1)
- for a singleton (like CharacterMotor) exactly one instance should exist
  during active gameplay

### Reading a field value

Once you have the instance GPA and the field's byte offset (measured from
probe 29 or from Il2CppDumper output):

```cpp
// read int32 at instance + fieldOffset
int32_t value;
GuestRead(instanceGpa + fieldOffset, &value, 4);
```

### Streaming a value

The recommended pattern is a polling loop in a background thread:

```cpp
void StreamLoop() {
    int32_t prevLane = 999;
    while (running) {
        int32_t lane;
        GuestRead(laneGpa, &lane, 4);
        if (lane != prevLane && (lane == -1 || lane == 0 || lane == 1)) {
            prevLane = lane;
            PipeSend("LANE %d\n", lane);
        }
        Sleep(16);  // ~60 Hz
    }
}
```

---

## 8. Stage 6 — Named Pipe Output

The DLL creates a named pipe server at `\\.\pipe\recon`. The protocol is
newline-terminated ASCII, unchanged from the Android 9 version.

### Messages from DLL → client

```
STATUS READY HVA_BASE <16-hex>   session banner, sent on connection
LANE -1                           player in LEFT lane
LANE 0                            player in CENTER lane
LANE 1                            player in RIGHT lane
LANE ?                            lane GPA stale (re-inject or SET_GPA)
PONG                              reply to PING
OK                                generic ack
ERR <message>                     error
```

### Commands from client → DLL

```
PING                              keepalive check
START                             begin streaming LANE updates
STOP                              pause streaming
READ                              one-shot READ of current lane
SET_GPA <16-hex>                  override lane GPA manually
HVA_BASE                          request current session HVA_BASE
```

### Computing the CE→GPA formula

```
GPA = CE_HVA - HVA_BASE
```

Where `HVA_BASE` is the host virtual address base of range[0], reported
in the `STATUS READY` banner. Useful for manually setting the lane GPA
from a Cheat Engine address when auto-discovery fails.

---

## 9. Adapting for a New Game

Everything in Stages 1–3 is identical for any game. Here is the exact
checklist for adding a new target:

### Step 1 — Dump the APK

```bash
# pull APK from device/emulator
adb shell pm path com.your.game
adb pull /data/app/.../base.apk

# extract the IL2CPP files
unzip base.apk lib/arm64-v8a/libil2cpp.so assets/bin/Data/Managed/Metadata/global-metadata.dat

# run Il2CppDumper
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/
```

### Step 2 — Find your target class

Open `output/dump.cs` and search for the game state you want to read.
Look for fields like current health, position, score, ammo, etc.

```csharp
// example from dump.cs
public class PlayerController // TypeDefIndex: 847
{
    // Fields
    public float health; // 0x68
    public int score; // 0x6C
    public Vector3 position; // 0x70
    public int currentWeapon; // 0x7C
}
```

Note:
- the **class name** (for Stage 4 name scan)
- the **field count** (for validation, from the type definition)
- the **field byte offset** (the hex comment after the field declaration)

### Step 3 — Update the four game-specific constants

In the DLL source (`recon_android11.cpp`), change:

```cpp
// === GAME-SPECIFIC — change these for each new target ===

static const char*  TARGET_CLASS_NAME  = "CharacterMotor"; // your class name
static const int    TARGET_FIELD_COUNT = 40;               // your class fc
static const int    LANE_FIELD_OFFSET  = 0x11C;            // your field offset
static const bool   LANE_IS_FLOAT      = false;            // true if float, false if int
```

### Step 4 — Adjust instance validation

The instance scan (Stage 5) uses a few sanity checks to avoid false
positives. Update these for your target:

```cpp
bool IsValidInstance(uint64_t gpa) {
    // example: health should be 0.0–100.0
    float hp; GuestRead(gpa + 0x68, &hp, 4);
    if (hp < 0.0f || hp > 100.0f) return false;
    
    // score should be non-negative
    int32_t score; GuestRead(gpa + 0x6C, &score, 4);
    if (score < 0) return false;
    
    return true;
}
```

### Step 5 — Update pipe output format

If you're reading something other than a -1/0/1 lane value, change the
`StreamLoop` output format and update your pipe client accordingly.

```cpp
// example: stream health as an integer percentage
void StreamLoop() {
    while (running) {
        float hp; GuestRead(fieldGpa, &hp, 4);
        int pct = (int)(hp);
        PipeSend("HP %d\n", pct);
        Sleep(50);
    }
}
```

### Step 6 — Recompile

```bash
# MinGW-w64 / MSYS2
g++ -O2 -shared -static -static-libgcc recon_android11.cpp -o recon_mygame.dll

# MSVC (VS x64 Native Tools prompt)
cl /LD /O2 /EHsc recon_android11.cpp /Fe:recon_mygame.dll /link /DLL psapi.lib
```

---

## 10. Non-Unity Games

The VBox bridge and page table machinery (Stages 1–3) work for any game.
For non-Unity engines, Stage 4 onwards changes:

### Unreal Engine (Android)

1. Dump `libUE4Game.so` / `libUE5Game.so` with Ghidra or IDA
2. Find `GObjects` and `GNames` by signature scan
3. Walk the `TUObjectArray` to find your target class
4. The x86_64 GVA→GPA translation (Stage 3) is identical

```cpp
// UObject first fields (UE4)
// +0x00  uint8[8]   ObjectFlags / internal
// +0x08  int32      InternalIndex
// +0x0C  FName      ClassPrivate
// +0x18  UObject*   OuterPrivate
```

### Native C++ / Custom Engine

Use pattern scanning instead of class walking:

```cpp
// define a byte signature for your target struct
uint8_t sig[] = { 0x48, 0x89, 0x5C, 0x24, '?', 0x57, 0x48, 0x83, 0xEC };
uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

// scan guest physical memory for the signature
for (auto& range : g_ramRanges) {
    for (uint64_t gpa = range.start; gpa < range.end; gpa += 0x10) {
        uint8_t buf[sizeof(sig)];
        GuestRead(gpa, buf, sizeof(sig));
        if (MatchMasked(buf, sig, mask, sizeof(sig))) {
            // candidate at gpa
        }
    }
}
```

### Java / Kotlin Games (non-IL2CPP)

Rare on BlueStacks (most games use IL2CPP for performance) but possible.
Use the Dalvik/ART heap layout: scan for class objects identified by the
`ClassObject` / `mirror::Class` magic, then find instance fields.
The GPA read path is identical.

### Godot

Godot Android exports use a native `.so`. Scan for `ClassDB` or known
GDScript function name strings as anchors, then walk the class tree.

---

## 11. Known Pitfalls

### Session-specificity

Every GPA, CR3, class address, and instance address changes on BlueStacks
restart. The DLL rediscovers everything automatically on each inject.
Never hardcode a GPA from one session into another.

### Inject timing

Inject **after** the game's main menu has loaded, not at BlueStacks startup.
The IL2CPP runtime initializes lazily — classes like `CharacterMotor` are
not present in memory until the game state that uses them has been entered
at least once. If a class is not found, let the game run further and retry.

### Paged-out pages

A PTE with bit 0 clear but a non-zero value is a swapped-out page.
`X64Translate` returns 0 for these. The workaround is to use measured
struct offsets (from live observation) rather than relying on field name
translation. The fields themselves are almost always present even when
their descriptor metadata is not.

### Multiple CR3 aliases

A single physical page can be mapped by 3–5 different CR3s simultaneously
(game process, kernel direct map, KPTI, shared libraries). Always validate
CR3 selection by confirming class objects exist under that space, not by
just finding the SONAME string.

### ELF header eviction

The `libil2cpp.so` ELF header page gets evicted from physical memory after
~1 hour of runtime. Always use the SONAME string in `.dynstr` as the anchor
for CR3 discovery, not the ELF header magic `0x7F454C46`.

### BlueStacks restart

BlueStacks occasionally restarts `HD-Player.exe` mid-session (observed
multiple times during research). The pipe disconnects, and all cached
GPAs, CR3s, and class addresses are invalid. The DLL handles this gracefully:
it re-enters Stage 1 on the next pipe connection and rediscovers everything.
The pipe client should reconnect automatically and expect a new `STATUS READY`
banner with a new `HVA_BASE`.

### Modded APKs

A modded APK may have different class names, field counts, or field offsets
than the official build. Always run `Il2CppDumper` on the **installed APK**,
not the Play Store version, if the two differ.

---

## 12. Constants Reference

### Fixed (do not change)

| Constant | Value | Source |
|----------|-------|--------|
| `PGM_RANGES_OFFSET` | `0x1010` | pVM struct offset for range list head |
| `NODE_NEXT_OFFSET` | `+0x10` | pNextR3 in PGM_RAM_RANGE node |
| `NODE_END_OFFSET` | `+0x28` | GCPhysLast in PGM_RAM_RANGE node |
| `NODE_DESC_OFFSET` | `+0x40` | pszDesc in PGM_RAM_RANGE node |
| `UVM_MAGIC` | `0x19700823` | VBox UVM struct signature |
| `METADATA_MAGIC` | `0xFAB11BAF` | IL2CPP global-metadata.dat header |
| `IL2CPP_NAME_OFF` | `+0x10` | name ptr in Il2CppClass |
| `IL2CPP_NS_OFF` | `+0x18` | namespaze ptr in Il2CppClass |
| `IL2CPP_FIELDS_OFF` | `+0x80` | fields ptr in Il2CppClass |
| `IL2CPP_FC_OFF` | `+0x124` | field_count u16 in Il2CppClass |
| `FIELDINFO_STRIDE` | `0x20` | size of one FieldInfo entry |
| `FIELDINFO_NAME_OFF` | `+0x00` | name ptr in FieldInfo |
| `FIELDINFO_OFFSET_OFF` | `+0x18` | byte offset i32 in FieldInfo |
| `PHYS_MASK` | `0x000FFFFFFFFFF000` | x86_64 PTE physical address mask |

### Game-specific (Subway Surfers / CharacterMotor)

| Constant | Value | Notes |
|----------|-------|-------|
| Target class | `CharacterMotor` | fc=40 |
| `_laneStateInfo` field | `+0x108` in instance | field index 27 |
| `IsChangingLane` | `+0x108` in instance | bool, 0↔1 |
| `LaneChangeDuration` | `+0x110` in instance | float ~0.23 s |
| `TargetLane` | **`+0x11C` in instance** | **int32, -1/0/1** |
| Lane encoding | `-1` / `0` / `1` | LEFT / CENTER / RIGHT |

---

## 13. What Changed from Android 9

A complete diff of every assumption that was wrong for Android 11:

| Item | Android 9 (Pie64) | Android 11 |
|------|-------------------|------------|
| Guest kernel | Linux ARM64 | **Linux x86_64** |
| RAM ranges | 1 (flat 0–0xE0000000) | **20 ranges; 2 are RAM** |
| Scan ceiling | `0xE0000000` | **must scan both ranges** |
| `pNextR3` offset | `+0x30` | **`+0x10`** |
| `GCPhysLast` offset | `+0x08` (was cb) | **`+0x28`** |
| Page table format | ARM64 3-level (TTBR0) | **x86_64 4-level (CR3)** |
| PT root register | TTBR0 | **CR3** |
| PT location | `0x0–0xE0000000` | **`0x100000000–0x11FFFFFFF`** |
| PT depth | 3-level (39-bit VA) | **4-level (48-bit VA)** |
| PTE format | ARM64 descriptors | **x86_64 PTE** |
| Discovery anchor | ELF header page | **SONAME string (resident)** |
| Target class | `CharacterProgressEntry` | **`CharacterMotor`** |
| Field count | 99 | **40** |
| `FieldInfo` stride | `0x18` | **`0x20`** |
| Lane field | GPA via field scan | **instance `+0x11C`** |
| Lane type | `float32` | **`int32`** |
| Lane values | `-1.0` / `0.0` / `1.0` | **`-1` / `0` / `1`** |

---

## Appendix — Pipe Client Quickstart (C#)

The existing `SubwayBot.cs` works unchanged. For a new client:

```csharp
using var pipe = new NamedPipeClientStream(".", "recon", PipeDirection.InOut);
await pipe.ConnectAsync(5000);

using var reader = new StreamReader(pipe, leaveOpen: true);
using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };

// read banner
string banner = await reader.ReadLineAsync();
// "STATUS READY HVA_BASE 00000178B0CD84F0"

await writer.WriteLineAsync("START");
string ack = await reader.ReadLineAsync(); // "OK"

while (true) {
    string line = await reader.ReadLineAsync();
    if (line.StartsWith("LANE ")) {
        int lane = int.Parse(line[5..]);
        // -1 = LEFT, 0 = CENTER, 1 = RIGHT
        Console.WriteLine($"Lane: {lane}");
    }
}
```

---

*All offsets and constants verified against live BlueStacks 5 / Android 11 /
BstkVMM.dll 2.1.24.117012 / HD-Player.exe. Structural constants are
build-stable across sessions. Session-specific values (GPAs, CR3s, instance
addresses) are re-discovered automatically on every inject.*
