# Subway Surfers Auto-Player — Technical Reference
**Session: Deliverables 1–5 | Verified Live | November 2026**
> **Note for contributors**: this document uses environment variable placeholders for machine-specific paths. Set these before running any commands:
> ```powershell
> # Required — set these for your machine
> $env:ANDROID_NDK_HOME = "$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358"  # adjust version if needed
> $env:CMAKE_EXE       = "C:\Program Files\CMake\bin\cmake.exe"              # adjust if cmake is elsewhere
> $env:PROJECT_ROOT    = "C:\path\to\your\Subway Surfers"                    # your project clone path
> ```
> `%ANDROID_NDK_HOME%`, `%CMAKE_EXE%`, `%PROJECT_ROOT%`, `<DEVICE_IP>`, and `<DEVICE_ID>` throughout this document refer to these values.

---


---

## 1. Environment

### Host
- OS: Windows (PowerShell 5.1)
- Working directory: `%PROJECT_ROOT%`
- CMake: `%CMAKE_EXE%`
- NDK: `%ANDROID_NDK_HOME%` (NDK r28, clang 19.0.1)
- NDK versions present: 26.1, 27.1, 28.2 — we use 28.2
- Set per session: `$env:ANDROID_NDK_HOME = "%ANDROID_NDK_HOME%"`

### Device
- Device ID (ADB): `<DEVICE_IP>:41589` (wireless ADB; earlier session used `<DEVICE_ID>`)
- Android version: 13
- Architecture: arm64-v8a only
- Root: confirmed (`su -c "whoami"` → `root`, uid=0, euid=0)
- Root mechanism: Magisk (shell context: `u:r:magisk:s0`)
- Capabilities: `CapEff: 000001ffffffffff` — full set
- SELinux: set to permissive via `setenforce 0` (resets on reboot)
- SELinux status after setenforce: `Permissive`

### Game Install
- Package: `com.kiloo.subwaysurf`
- Base APK: `/data/app/~~pj-qdMbpEBNPOKY2w3_crA==/com.kiloo.subwaysurf-1o5d582Ks8uS5YANhInSVA==/base.apk` (242.7 MB)
- Split APKs:
  - `split_config.arm64_v8a.apk` (33.4 MB)
  - `split_gpdeku.apk` (115 KB)
  - `split_gpdeku.config.arm64_v8a.apk` (168 KB)
- Lib dir: `.../com.kiloo.subwaysurf-1o5d582Ks8uS5YANhInSVA==/lib/arm64/`
- Game data dir: `/data/data/com.kiloo.subwaysurf/`
- Game UID: `u0_a288` = uid 10288
- Typical observed PIDs: 12624, 16497, 22552, 26466 (changes each launch)

---

## 2. Game Binary

### Runtime
- **IL2CPP** (not Mono) — confirmed by presence of `libil2cpp.so` and `libunity.so`, absence of `libmono.so`
- Unity version: 2021–2022 era (inferred from metadata v31)

### Native Libraries (full list from lib/arm64/)
```
libFirebaseCppAnalytics.so
libFirebaseCppApp-12_10_1.so
libFirebaseCppCrashlytics.so
libFirebaseCppMessaging.so
libNatCorder.so
libNatRender.so
libapplovin-native-crash-reporter.so
libcrashlytics-common.so
libcrashlytics-handler.so
libcrashlytics-trampoline.so
libcrashlytics.so
libdatastore_shared_counter.so
libgpdeku.so
libil2cpp.so          ← primary target
libmain.so
libnms.so
libpglarmor.so        ← anti-cheat; NEVER TOUCH
libtt_ugen_layout.so
libunity.so
libunitycoherencenative.so
```

### Anti-Cheat: libpglarmor.so
- PGL Armour — Chinese anti-cheat/integrity library
- Samples running threads, checks for external ptrace attachment
- We detach (PTRACE_DETACH) before the game's main loop is running — injection happens during early process init
- Rules: never patch it, never hook it, never suspend its threads, never read its memory from outside
- Our posture: fully in-process after injection, no external memory reader

---

## 3. Metadata

### Location
- Inside `base.apk` at: `assets/bin/Data/Managed/Metadata/global-metadata.dat`
- File size: **16,363,736 bytes** (16 MB)
- Extracted to: `.\work\global-metadata.dat`

### Header
- Magic: `0xFAB11BAF` (confirmed)
- Version: **31** (Unity 2021–2022 era IL2CPP)
- Header size: 0x100 bytes = 256 bytes
- Pair count: **31 pairs** (each pair = offset + size, 8 bytes)
- Pairs start at offset 8

### Confirmed Pair Layout
| Pair | Offset | Size | Content |
|------|--------|------|---------|
| 2 | 0xCD3D8 | 2,451,276 | String table (class/method names) |
| 5 | 0x38AB84 | 4,462,164 | Method definitions (123,949 × 36B) |
| 19 | 0xC84ED4 | 1,793,176 | Type definitions (20,377 × 88B) |

### Struct Sizes (confirmed by divisibility + content validation)
- `Il2CppTypeDefinition`: **88 bytes**
  - nameIndex @ +0 (uint32)
  - nsIndex @ +4 (uint32)
  - methodStart @ +56 (uint32)
  - method_count @ +84 (uint16)
  - declaringTypeIndex @ +16 (uint32)
- `Il2CppMethodDefinition`: **36 bytes**
  - nameIndex @ +0 (uint32)
  - declaringType @ +4 (uint32)

### Metadata Dump Output
- Tool: `.\tools\walk_metadata.py` (custom, pure Python stdlib)
- Output: `.\work\metadata_dump.json`
- Stats: **20,377 types**, **123,949 methods**
- Run command: `py -3 .\tools\walk_metadata.py .\work\base.apk -o .\work\metadata_dump.json`
- Key fix applied: `cstr()` must allow empty namespace strings (ns="" is valid, `not raw` check was wrong)
- Key fix applied: `ms == 0xFFFFFFFF` = module-level entry with no methods — skip accumulator, require mc==0
- Typedef table: pair[19], td_len=88, ms_off=56 (confirmed by probe: `<Module>` at index 0 with ms=0, mc=1)

---

## 4. IL2CPP Exported Symbols

Verified on-device using `strings libil2cpp.so | grep symbol_name`:

### Present (all confirmed)
```
il2cpp_domain_get
il2cpp_domain_get_assemblies
il2cpp_image_get_class_count
il2cpp_image_get_class
il2cpp_assembly_get_image
il2cpp_class_get_name
il2cpp_class_get_namespace
il2cpp_class_get_methods
il2cpp_method_get_name
il2cpp_image_get_name
il2cpp_class_get_fields
il2cpp_field_get_name
il2cpp_field_get_offset
il2cpp_field_get_flags
il2cpp_field_get_type
il2cpp_class_from_type
il2cpp_class_is_enum
il2cpp_field_static_get_value
il2cpp_class_get_parent
il2cpp_object_get_class
```

### Absent (confirmed missing from .dynsym)
```
il2cpp_method_get_pointer   ← NOT exported by this build
```
**Workaround**: self-calibrating MethodInfo slot scan (see Section 7).

### Additional symbols needed but not in original spec
```
il2cpp_assembly_get_image   ← needed to go from assembly to image
il2cpp_image_get_class_count ← needed for loop bound
```
Both present. The original spec's symbol list was incomplete.

### dlopen Strategy
Short name `"libil2cpp.so"` with `RTLD_NOLOAD` fails when the linker cached the lib under its full path. Fallback: scan `/proc/self/maps` for `r-xp` mapping containing `libil2cpp.so`, extract full path, `dlopen(full_path, RTLD_LAZY | RTLD_GLOBAL)`.

---

## 5. Key Classes

### Hook Target
| Class | Namespace | Confirmed Runtime Methods |
|-------|-----------|--------------------------|
| RunnerStatePlaying | SYBO.Subway.State | OnInitSystems, OnEnterState, **OnStateUpdate**, .ctor |
| RunnerStateMainMenu | SYBO.Subway.State | OnStateUpdate (used for menu-phase verification) |

**Critical deviation**: spec said hook `Update`. Runtime method list for `RunnerStatePlaying` is exactly `{OnInitSystems, OnEnterState, OnStateUpdate, .ctor}` — `Update` does not exist. `OnStateUpdate` is the per-frame tick. This was discovered by live method enumeration, not documentation.

### Character System
```
SYBO.RunnerCore.Character.CharacterMotor         — main motor, owns lane/speed/state
SYBO.RunnerCore.Character.LaneChangeAbility
SYBO.RunnerCore.Character.LaneChangeAbilityInstance
SYBO.RunnerCore.Character.JumpAbility
SYBO.RunnerCore.Character.JumpAbilityInstance
SYBO.RunnerCore.Character.RollAbility
SYBO.RunnerCore.Character.RollAbilityInstance
SYBO.RunnerCore.Character.CharacterInputController
SYBO.RunnerCore.Character.CharacterAbstractInputController
```

### Input System
```
SYBO.Common.Input.InputSwipe
SYBO.Common.Input.InputProviderGesture    — entry point for swipe injection
SYBO.Common.Input.InputProviderController
SYBO.Common.Input.InputAction
SYBO.Common.Input.InputActionType
SYBO.Common.Input.InputProviderKeyboard
SYBO.Common.Input.InputProviderTouch
```

### Score/Game State
```
SYBO.Subway.ScoreMultiplierManager
SYBO.Subway.GameController
SYBO.Subway.State.RunnerStateMachine
SYBO.Subway.Meta.CoreRunner.CoreRunnerManager   — holds _prevPoints (Int64)
SYBO.Subway.GameDataLocator
```

### Motor State Subclasses (13 registered, identified by class header pointer)
| Class | State String | Gameplay Meaning |
|-------|-------------|-----------------|
| RunningState | "running" | Normal ground run |
| JumpingState | "jumping" | In-air after jump |
| RollingState | "rolling" | Ducking/rolling under obstacle |
| FallingState | "falling" | Falling after jump apex |
| DeathState | "dead" | Hit obstacle, run ended |
| DivingState | "diving" | Dive roll |
| FlyingState | "flying" | Jetpack / pogo stick |
| IdleState | "idle" | Not running (menu/start) |
| TreadmillingState | "treadmilling" | On treadmill pad |
| DeterministicJumpingState | "detjumping" | Physics-locked jump |
| CustomJumpingState | "customjumping" | Power-modified jump |
| FrontalImpactOffset | varies | Impact frame state |
| (remaining) | varies | Other impact states |

### Lane Types
```
LaneStateInfo    — inline struct in CharacterMotor
LaneChangeStarted
```

### Level Generation
```
SYBO.RunnerCore.BuildingBlocks.Chunk
SYBO.RunnerCore.BuildingBlocks.ChunkBuilder
SYBO.RunnerCore.BuildingBlocks.ChunkBoundarySlot
SYBO.RunnerCore.BuildingBlocks.SpawnData (from metadata)
```

---

## 6. Build System

### Project Structure
```
Subway Surfers/
├── CMakeLists.txt              (top-level, includes agent + injector + common)
├── agent/
│   ├── CMakeLists.txt          (builds libsyncutil.so)
│   ├── include/agent/logging.h
│   └── src/bootstrap.cpp       (all agent logic)
├── injector/
│   ├── CMakeLists.txt
│   └── src/main.cpp
├── common/
│   ├── CMakeLists.txt
│   └── include/common/paths.h  (all file path constants)
├── scripts/
│   ├── build.ps1
│   ├── push_and_run.ps1
│   └── logcat.ps1
├── tools/
│   ├── walk_metadata.py
│   └── probe_td.py
└── work/
    ├── base.apk
    ├── global-metadata.dat
    └── metadata_dump.json
```

### CMake Flags
```
Target ABI:     aarch64-none-linux-android33
Compiler:       clang 19.0.1 (NDK r28)
C++ standard:   -std=c++20
Optimization:   -O3 -DNDEBUG
Agent flags:    -fPIC -fvisibility=hidden
Injector flags: -fPIE
Both:           -Wall -Wextra -Werror -g
```

### Link Libraries
```
agent:    log dl android
injector: (none extra)
```

### Build Commands
```powershell
# Full build
$env:ANDROID_NDK_HOME = "%ANDROID_NDK_HOME%"
cd "%PROJECT_ROOT%"
.\scripts\build.ps1

# Agent only
& "%CMAKE_EXE%" --build build --target agent 2>&1

# Injector only
& "%CMAKE_EXE%" --build build --target injector 2>&1
```

### Output Files
```
build\agent\libsyncutil.so    (agent, arm64)
build\injector\injector       (injector ELF, arm64)
```

---

## 7. Injection System

### Why /data/app lib dir is unwritable
The `~~pj-qdMbpEBNPOKY2w3_crA==` path uses Android's OTA directory naming. These directories sit on a read-only overlay filesystem. Even root with full capabilities (`CapEff: 000001ffffffffff`) cannot write there — it is a filesystem-level restriction, not a permission bit. `chown` and `chmod` also fail silently or return permission denied.

### Why /data/data works
`/data/data/com.kiloo.subwaysurf/` is owned by `u0_a288:u0_a288` (uid 10288). Root can write here (DAC: root bypasses ownership). The game process (uid 10288) can execute from `app_data_file` SELinux context. Confirmed by AVC audit log:
```
avc: granted { execute } for path="/data/data/com.kiloo.subwaysurf/libsyncutil.so"
scontext=u:r:untrusted_app:s0:c32,c257,c512,c768
tcontext=u:object_r:app_data_file:s0:c32,c257,c512,c768
```

### Injection Algorithm
```
1. Poll /proc/*/cmdline every 100ms, match "com.kiloo.subwaysurf"
   Timeout: 180 seconds

2. Sleep 500ms (let process finish early init)

3. Wait for libil2cpp.so in /proc/<pid>/maps (15s budget)
   Derive install lib/arm64 dir from maps path

4. Stage agent:
   cp /data/local/tmp/libsyncutil.so
      /data/data/com.kiloo.subwaysurf/libsyncutil.so
   chmod 755

5. Find dlopen in target:
   - Read /proc/<pid>/maps for libdl.so r-xp mapping → target_libdl_base
   - Read /proc/self/maps for libdl.so → self_libdl_base
   - local_dlopen = dlsym(RTLD_DEFAULT, "dlopen")
   - remote_dlopen = local_dlopen - self_libdl_base + target_libdl_base

6. PTRACE_ATTACH → wait for SIGSTOP (signal 19)

7. PTRACE_GETREGSET(NT_PRSTATUS) → save user_pt_regs
   struct: 31 × uint64 regs + sp + pc + pstate = 272 bytes

8. Find scratch region:
   Largest [anon:dalvik-*] RW mapping in target maps
   Observed: 0x02000000-0x12000000 = 256MB [anon:dalvik-main space]
   Path string written at mid-point, 8-byte aligned

9. Find BRK slot:
   libdl.so r-xp region + 0x400
   libpglarmor.so explicitly excluded from search
   Save original 8 bytes at slot
   Write 0xD4200000D4200000 (two arm64 brk #0 instructions)

10. Redirect execution:
    x0 = path_string_address (in scratch)
    x1 = RTLD_NOW (= 2)
    lr = brk_slot_address
    pc = remote_dlopen

11. PTRACE_SETREGSET → PTRACE_CONT

12. Wait for SIGTRAP (brk #0 fires when dlopen returns through lr)
    Read x0 from registers = dlopen return value (handle)

13. Restore:
    - Original registers (PTRACE_SETREGSET)
    - Scratch bytes (PTRACE_POKEDATA)
    - BRK slot bytes (PTRACE_POKEDATA)

14. PTRACE_DETACH

15. Poll /data/data/com.kiloo.subwaysurf/.syncutil_loaded every 200ms
    for 5 seconds. Check pid field matches target pid.
```

### Observed dlopen Handles (non-NULL = success)
```
pid=12624: 0x84601acea7523389
pid=16497: 0x7b6d9c027aae8399
pid=22552: 0xe2cb9e4e07db89ad
```
Non-NULL handle confirms agent loaded. The misleading "returned NULL" error message was a code path issue (the error string was wrong — handle was clearly non-zero in the logs).

### Push and Inject Commands
```powershell
# Push
adb push build\agent\libsyncutil.so /data/local/tmp/libsyncutil.so
adb push build\injector\injector /data/local/tmp/injector
adb shell "su -c 'chmod 755 /data/local/tmp/injector'"

# Stage agent into game data dir
adb shell "su -c 'cp /data/local/tmp/libsyncutil.so /data/data/com.kiloo.subwaysurf/libsyncutil.so && chmod 755 /data/data/com.kiloo.subwaysurf/libsyncutil.so && echo OK'"

# Kill, relaunch, inject
adb shell "su -c 'am force-stop com.kiloo.subwaysurf'"
adb shell "su -c 'am start -n com.kiloo.subwaysurf/com.unity3d.player.UnityPlayerActivity'"
Start-Sleep -Seconds 12
adb shell "su -c '/data/local/tmp/injector inject'"
```

---

## 8. Agent Architecture

### Constructor
```cpp
__attribute__((constructor(102))) static void agent_bootstrap()
```
- Writes `.syncutil_loaded` with `pid=N`
- Calls `load_target_config()` — reads `.syncutil_target` if present
- Spawns `il2cpp_walk_thread` via `pthread_create`, immediately detaches
- Returns immediately — injector's remote dlopen thread must not block

### Walk Thread
```
Sleep 2000ms
→ Resolve all il2cpp symbols from libil2cpp.so
→ Walk: domain → 168 assemblies → images → 20,377 classes
→ Find target class by namespace + name
→ Log all runtime methods on matched class
→ resolve_method_code_ptr() → code pointer
→ install_hook() → trampoline page
→ patch_method() → patch site
→ init_state_reader() → field maps, BFS, field picks
```

### Target Config File (`.syncutil_target`)
```
Line 1: namespace   (e.g. "SYBO.Subway.State")
Line 2: class name  (e.g. "RunnerStatePlaying")  — empty = discovery mode
Line 3: method name (e.g. "OnStateUpdate")
```
Discovery mode: logs all classes in namespace with their method lists. No hook installed.

Default target (hardcoded fallback):
- Namespace: `SYBO.Subway.State`
- Class: `RunnerStatePlaying`
- Method: `OnStateUpdate`

---

## 9. MethodInfo Self-Calibrating Code Pointer Resolution

Required because `il2cpp_method_get_pointer` is not exported.

```
1. Call il2cpp_method_get_name(mi) → runtime-authoritative name string
   Validate the returned pointer is in a readable mapping.

2. Scan MethodInfo as array of pointer-sized slots (first 24):
   Find the slot whose value == name string pointer.
   This is name_slot. Observed: name_slot = 3 (name at MethodInfo+24).

3. Collect all slots BELOW name_slot whose values fall in
   libil2cpp.so exec-range mappings. Deduplicate by value.

4. Priority:
   - slot[0] wins if it qualifies (classic layout: code pointer first)
   - else slot[name_slot - 2] wins
   - else single remaining candidate wins
   - multiple candidates with no priority = refusal

5. Observed live:
   - name_slot = 3
   - code pointer at slot[0] = MethodInfo+0
   - method address: 0x71fa0dafb0 (in libil2cpp.so exec range)
```

---

## 10. Trampoline

### Layout (92 bytes in one mmap'd RWX page, MAP_ANONYMOUS|MAP_SHARED)

```
page+0  .. +15:  4 stolen instructions from method prologue (re-executed verbatim)
page+16 .. +19:  stp x0, x1,   [sp, #-16]!   = 0xA9BF07E0
page+20 .. +23:  stp x2, x3,   [sp, #-16]!   = 0xA9BF0FE2
page+24 .. +27:  stp x4, x5,   [sp, #-16]!   = 0xA9BF17E4
page+28 .. +31:  stp x6, x7,   [sp, #-16]!   = 0xA9BF1FE6
page+32 .. +35:  stp x29, x30, [sp, #-16]!   = 0xA9BF7BFD
page+36 .. +39:  ldr x17, #48                 = 0x58000191  → reads literal at page+84
page+40 .. +43:  blr x17                      = 0xD63F0220  → hook fn; lr = page+44
page+44 .. +47:  ldp x29, x30, [sp], #16      = 0xA8C17BFD
page+48 .. +51:  ldp x6, x7,   [sp], #16      = 0xA8C11FE6
page+52 .. +55:  ldp x4, x5,   [sp], #16      = 0xA8C117E4
page+56 .. +59:  ldp x2, x3,   [sp], #16      = 0xA8C10FE2
page+60 .. +63:  ldp x0, x1,   [sp], #16      = 0xA8C107E0
page+64 .. +67:  ldr x16, #8                  = 0x58000050  → reads literal at page+72
page+68 .. +71:  br x16                       = 0xD61F0200  → orig+16
page+72 .. +79:  [8-byte literal: orig+16 address]
page+80 .. +83:  (padding / unused)
page+84 .. +91:  [8-byte literal: hook fn address]
```

**Hook function signature**: `extern "C" void syncutil_frame_hook(uintptr_t thisp, uintptr_t method)`
- x0 = hooked instance (`this` pointer of RunnerStatePlaying)
- x1 = MethodInfo pointer

### Patch Site (16 bytes at method start)
```
+0:  0x58000050   ldr x16, #8    (reads 8 bytes at +8)
+4:  0xD61F0200   br x16         (jump to trampoline)
+8:  [8-byte trampoline address, little-endian]
```

### Write Order (critical — literals before instructions)
```cpp
memcpy(page + 72, &orig_next, 8);        // literal first
memcpy(page + 84, &hook_fn_addr, 8);     // literal first
asm volatile("" ::: "memory");           // compiler barrier
memcpy(page + 0, insns_a, 44);           // instructions second
memcpy(page + 44, insns_b, 28);
asm volatile("" ::: "memory");
__builtin___clear_cache(page, page + 92);
```

### PC-Relative Instruction Gate
Reject any stolen instruction matching these masks (causes SIGILL if relocated):

| Instruction | Mask | Value |
|-------------|------|-------|
| b / bl | 0x7C000000 | 0x14000000 |
| b.cond | 0xFF000000 | 0x54000000 |
| adrp | 0x9F000000 | 0x90000000 |
| adr | 0x9F000000 | 0x10000000 |
| cbz/cbnz | 0x7E000000 | 0x34000000 |
| tbz/tbnz | 0x7E000000 | 0x36000000 |
| ldr literal 32b | 0x3F000000 | 0x18000000 |
| ldr literal 64b | 0x3F000000 | 0x58000000 |

### Observed Stolen Prologue (RunnerStatePlaying::OnStateUpdate)
```
fc1d0fea  6d00a3e9  f9000ffe  a9024ff4
```
All PC-relative-free. Install succeeded.

### ARM64 Encoding Bug (SIGILL #2 — fixed)
Wrong: `stp x0,x0` (Rt2 bit missing) — unpredictable, deterministic SIGILL at page+0x3C
Right: `0xA9BF07E0` for `stp x0, x1, [sp, #-16]!` — Rt2=1 required (bits 14..10 = 00001)
Same issue on ldp: `0xA8C107E0` for `ldp x0, x1, [sp], #16`

### Trampoline Layout Bug (SIGILL #1 — fixed)
Original layout had epilogue at page+44 (correct) but `ldr x17, #8` at page+36 pointed to page+44 — the return address itself, not a literal. Hook `ret` landed on the literal bytes and executed them as code. Fixed by moving literals to page+72 and page+84, with `ldr x17, #48` from page+36.

---

## 11. State Reader

### Field Map Infrastructure
- `build_field_map(klass, fm)`: walks base class chain (up to 8 levels via `class_get_parent`)
- Instance fields only: skips `FIELD_ATTRIBUTE_STATIC` (flag `0x0010`)
- Stores: field name (48 chars), reported offset (int32)
- Registry: `g_class_maps[64]` keyed by klass pointer — never rebuilt

### Value-Type Offset Correction (critical)
`il2cpp_field_get_offset` returns offset as if the field's type were boxed (16-byte `Il2CppObject` header prepended). For inline structs, actual memory is at `reported_offset - 16`.

Detection at runtime:
```cpp
uintptr_t first_word;
safe_read_ptr(motor_obj, reported_offset, &first_word);
bool is_heap_ref = ((const void*)first_word == laneinfo_klass);
int hdr_fix = is_heap_ref ? 0 : 16;
// actual read: safe_read_*(base, reported_offset - hdr_fix, ...)
```

### CharacterMotor Fields (confirmed live)
| Field | Type | Purpose |
|-------|------|---------|
| `_laneStateInfo` | LaneStateInfo (inline struct) | Lane position, changing flag, target |
| `Velocity` | Vector3 (float[3]) @ motor+468 | Current velocity — magnitude = speed |
| `_currentState` | MotorState (reference) | Pointer to active state subclass object |

### LaneStateInfo Fields (confirmed live)
| Field | Type | Value Range | Meaning |
|-------|------|-------------|---------|
| `SourceLanePosition` | float | -1.0, 0.0, +1.0 | Current lane (position units) |
| `IsChangingLane` | bool | 0/1 | True during active lane change |
| `TargetLane` | int | -1, 0, +1 | Destination lane during change |

### Lane Calculation
```
lane_index = floor(SourceLanePosition + 0.5) + 1
During change: lane_index = TargetLane + 1
Clamp to [0, 2]. -1 = unknown.
JSON output: 0=left, 1=center, 2=right
```

Verified live:
```
lanePos=-1.00 → lane=0 (left)
lanePos= 0.00 → lane=1 (center)  
lanePos=+1.00 → lane=2 (right)
```

### Score Chain
- Path: `RunnerStatePlaying` → [BFS/static ref] → `CoreRunnerManager._prevPoints`
- Field: `_prevPoints` (Int64)
- Why not the displayed counter: `_prevPoints` is updated every frame, the displayed counter lags

### Identity Ledger
- Purpose: whitelist of klass pointers whose il2cpp API calls are allowed
- Walk-time entries: `evictable=true` (can be replaced)
- Runtime admissions: keyword gate on class name, `safe_str` guard on name/ns
- `kMaxLedger = 512` (was 128 — OOB write bug)
- Admission keyword list: Motor, Runner, Character, Controller, Score, Lane, State, Input, Ability, Player, Game, Manager, System, Provider, Scene, Extensions, Service, Speed, List, and any class name containing `[]`

### BFS Object Chain Discovery
```
Parameters:
  kBfsMaxQueue   = 128  (BFS queue size)
  kBfsMaxDepth   = 8    (max reference hops)
  kBfsMaxItems   = 24   (array items probed per hop)
  kBfsMaxVisited = 256  (dedup set)

For each node:
  1. Read header word (safe_read_ptr at offset 0)
  2. Check header against ledger — unknown headers trigger ledger_try_admit()
  3. Build field map for this klass
  4. For each instance field:
     a. safe_read_ptr at field offset
     b. Heuristic: value > 0x100000, alignment (& 7) == 0, readable 16 bytes
     c. Read candidate's header word
     d. If header == want_klass → chain found
     e. If array: probe up to 24 items via [32 + 8*i] offsets
     f. Admit unknown headers via ledger_try_admit()
     g. Enqueue admitted candidates
```

### Guard Wrap Bug (crash-class, fixed)
```cpp
// WRONG — m.end - addr underflows for high addresses, check always passes:
if (addr >= m.start && len <= m.end - addr && (m.prot & PROT_READ))

// CORRECT — explicit upper bound check:
if (addr >= m.start && addr < m.end && len <= m.end - addr && (m.prot & PROT_READ))
```
This caused SIGSEGV at address 0x143340000 — a garbage pointer blessed by the underflow.

### Maps Cache
- Snapshot taken at walk thread completion (install time)
- Refreshed lazily on frame thread: at most every 250ms
- `g_maps_dirty = true` when a read fails → triggers next refresh
- Frame thread only refreshes its own reads, never the walk thread's

---

## 12. State File

### Path
`/data/data/com.kiloo.subwaysurf/.syncutil_state`

### Format
Single JSON line, overwritten each frame (~60Hz):
```json
{"lane":1,"state":"running","score":2856,"speed":164.70,"changing":false}
```

### Fields
| Key | Type | Values | Source |
|-----|------|--------|--------|
| lane | int | 0=left, 1=center, 2=right, -1=unknown | LaneStateInfo.SourceLanePosition |
| state | string | "running","jumping","rolling","falling","dead","flying","idle",... | _currentState class identity |
| score | int64 | ≥0 or -1 | CoreRunnerManager._prevPoints |
| speed | float | ≥0.0 or -1.0 | \|Velocity\| magnitude |
| changing | bool | true/false | LaneStateInfo.IsChangingLane |

### Error States
```json
{"error":"chain_not_resolved"}   // motor not found via BFS yet
{"error":"read_failed"}          // safe_read returned false
```

### Live Verification Table
```
frame  lanePos  changing  targetLane  lane  state    score  speed
2100   0.00     0         1           1     rolling  2771   135.9
2160   1.00     1         0           1     running  2856   164.7
2220   1.00     0         0           2     running  2948   137.4
2280   0.00     0         -1          1     jumping  3017   161.1
2400   -1.00    0         0           0     rolling  3143   139.7
2520   0.00     0         -1          1     falling  3269   145.5
```

---

## 13. File Interface (Complete)

| File | Written By | Read By | Format | Frequency |
|------|-----------|---------|--------|-----------|
| `/data/local/tmp/libsyncutil.so` | adb push | injector (staging) | ELF .so | once |
| `/data/local/tmp/injector` | adb push | shell | ELF executable | once |
| `/data/data/com.kiloo.subwaysurf/libsyncutil.so` | injector (cp) | Android linker | ELF .so | each inject |
| `/data/data/com.kiloo.subwaysurf/.syncutil_loaded` | agent constructor | injector (verify) | `pid=N\n` | on load |
| `/data/data/com.kiloo.subwaysurf/.syncutil_tick` | agent frame hook | external | `tick frame=N\n` | every 60 frames |
| `/data/data/com.kiloo.subwaysurf/.syncutil_state` | agent frame hook | decision engine | JSON line | every frame (~60Hz) |
| `/data/data/com.kiloo.subwaysurf/.syncutil_target` | developer | agent bootstrap | 3 lines: ns/class/method | on demand |
| `/data/data/com.kiloo.subwaysurf/.syncutil_stream` | developer (touch) | agent frame hook | presence = enabled | on demand |
| `/data/data/com.kiloo.subwaysurf/.syncutil_decision` | decision engine | agent input writer | `{"action":"X"}\n` | every frame |

### .syncutil_target Format
```
SYBO.Subway.State
RunnerStatePlaying
OnStateUpdate
```
Empty line 2 = discovery mode (logs classes, no hook).

### .syncutil_decision Actions
```json
{"action":"swipe_left"}
{"action":"swipe_right"}
{"action":"jump"}
{"action":"roll"}
{"action":"none"}
```

---

## 14. Bugs Found and Fixed

| # | Bug | Symptom | Fix |
|---|-----|---------|-----|
| 1 | Guard wrap in `in_readable_mapping` | SIGSEGV at 0x143340000 | Add `addr < m.end` check before `m.end - addr` |
| 2 | Ledger overflow (`kMaxLedger=128`) | OOB array writes | Raise to 512, add eviction |
| 3 | Trampoline layout: epilogue at wrong offset | SIGILL #1 at page+0x3C | Move epilogue to page+44, literals to page+72/84 |
| 4 | ARM64 stp/ldp Rt2 bit missing | SIGILL #2 — `stp x0,x0` unpredictable | Correct encodings: 0xA9BF07E0 / 0xA8C107E0 |
| 5 | b.cond missing from PC-relative gate | Potential SIGILL on future targets | Add mask 0xFF000000 / val 0x54000000 |
| 6 | `!seen &&` logic bug in method scan | Only method #0 ever name-compared | Fix loop condition |
| 7 | `.syncutil_loaded` marker dropped in d4 rewrite | Injector verification protocol broken | Restore in constructor(102) |
| 8 | `mmap` returns `void*`, C++ won't cast | Build error | Add `(uint8_t*)` cast |
| 9 | value-type field offsets include 16B boxing header | Garbage data for inline structs | Subtract 16 for inline, detect at runtime |
| 10 | `dlopen("libil2cpp.so", RTLD_NOLOAD)` fails | "1 of 10 symbols missing" | /proc/self/maps scan fallback to full path |

---

## 15. Deviations from Original Spec

| Item | Spec Said | Reality | Evidence |
|------|-----------|---------|----------|
| Hook method | `Update` | `OnStateUpdate` | Live method enumeration: {OnInitSystems, OnEnterState, OnStateUpdate, .ctor} |
| `il2cpp_method_get_pointer` | Present | Absent | readelf on device: zero occurrences in .dynsym |
| Staging path | `/data/app/.../lib/arm64/` | `/data/data/com.kiloo.subwaysurf/` | /data/app is read-only overlay fs |
| Symbol list | 10 symbols | 12 needed | `il2cpp_assembly_get_image` and `il2cpp_image_get_class_count` missing from spec |
| Verification target | RunnerStatePlaying (in-run) | RunnerStateMainMenu (menu) for initial verify | RunnerStatePlaying only ticks during active run |

---

## 16. Quick Reference Commands

```powershell
# Environment
$env:ANDROID_NDK_HOME = "%ANDROID_NDK_HOME%"
cd "%PROJECT_ROOT%"

# Build all
.\scripts\build.ps1

# Build agent only
& "%CMAKE_EXE%" --build build --target agent 2>&1

# Push and stage
adb push build\agent\libsyncutil.so /data/local/tmp/libsyncutil.so
adb push build\injector\injector /data/local/tmp/injector
adb shell "su -c 'chmod 755 /data/local/tmp/injector'"
adb shell "su -c 'cp /data/local/tmp/libsyncutil.so /data/data/com.kiloo.subwaysurf/libsyncutil.so && chmod 755 /data/data/com.kiloo.subwaysurf/libsyncutil.so && echo OK'"

# Kill, relaunch, inject
adb shell "su -c 'am force-stop com.kiloo.subwaysurf'"
adb shell "su -c 'am start -n com.kiloo.subwaysurf/com.unity3d.player.UnityPlayerActivity'"
Start-Sleep -Seconds 12
adb shell "su -c 'rm -f /data/data/com.kiloo.subwaysurf/.syncutil_loaded'"
adb shell "su -c '/data/local/tmp/injector inject'"

# Verify agent running
adb logcat -d | Select-String "SyncUtil" | Select-Object -Last 20

# Watch live
adb logcat -s SyncUtil:*

# Read state
adb shell "su -c 'cat /data/data/com.kiloo.subwaysurf/.syncutil_state'"

# Read tick
adb shell "su -c 'cat /data/data/com.kiloo.subwaysurf/.syncutil_tick'"

# Enable stream mode
adb shell "su -c 'touch /data/data/com.kiloo.subwaysurf/.syncutil_stream'"

# Check game running
adb shell "su -c 'sh /data/local/tmp/getmaps.sh'" | Select-String "kiloo"

# Delete stale marker
adb shell "su -c 'rm -f /data/data/com.kiloo.subwaysurf/.syncutil_loaded'"

# SELinux permissive
adb shell "su -c 'setenforce 0 && getenforce'"

# Pull metadata APKs
.\scripts\pull_metadata.ps1

# Run metadata walker
py -3 .\tools\walk_metadata.py .\work\base.apk -o .\work\metadata_dump.json

# Retarget to discovery mode (SYBO.Subway.State namespace)
adb shell "su -c 'printf \"SYBO.Subway.State\n\nOnStateUpdate\" > /data/data/com.kiloo.subwaysurf/.syncutil_target'"

# Check field symbols in libil2cpp
adb shell "su -c 'strings /data/app/~~pj-qdMbpEBNPOKY2w3_crA==/com.kiloo.subwaysurf-1o5d582Ks8uS5YANhInSVA==/lib/arm64/libil2cpp.so | grep il2cpp_field'"
```

---

## 17. What to Build Next (Deliverable 6+)

### Input Writer
Target: `SYBO.Common.Input.InputProviderGesture`
Method to find: `AddSwipe` or equivalent (use discovery mode on `SYBO.Common.Input` namespace)
Call convention: `(this_ptr, int direction)` where 0=left, 1=right, 2=up(jump), 3=down(roll)
Calling method: resolve via `resolve_method_code_ptr`, cast to function pointer, call directly

### Decision Engine
- Read state from `g_reader` directly (same process — no file I/O needed for reads)
- Write decisions to `.syncutil_decision` for external override capability
- Timing: 80–150ms delay before firing (randomized), 300ms cooldown per action type
- Miss rate: 1-in-20 for stream mode
- Jitter: ±15ms on all fires

### Obstacle Lookahead
Classes to explore (in metadata, not yet read live):
- `SYBO.RunnerCore.BuildingBlocks.ChunkBuilder`
- `SYBO.RunnerCore.BuildingBlocks.Chunk`
- `SYBO.RunnerCore.BuildingBlocks.ChunkBoundarySlot`
- `SYBO.RunnerCore.BuildingBlocks.SpawnData`
Approach: add to ledger walk, run BFS from hook root, log field lists in discovery mode.

### Stream Mode (Render Hook)
- Toggle: presence of `.syncutil_stream`
- Hook Unity's render present call (EGL `eglSwapBuffers` or Unity's internal present)
- Strip any agent-drawn overlays before frame reaches compositor
- Input simulation via gesture injection looks like normal swipes — no visual artifact to strip on that side

---

*End of reference document. All data verified live on device during session, November 2026.*