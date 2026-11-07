# Subway Surfers 3.70.2 — Reverse Engineering Reference
**Source:** `global-metadata.dat` (IL2CPP v31, Unity, ARM64)  
**Package:** `com.kiloo.subwaysurf`  
**Frida process name:** `Subway Surf` (PID varies — use `frida-ps -U` to find)  
**libil2cpp.so base:** confirmed at runtime (~81MB)

---

## 1. Runtime Architecture

| Layer | Detail |
|---|---|
| Engine | Unity (IL2CPP backend) |
| Metadata version | 31 (unencrypted `global-metadata.dat`) |
| Scripting | C# compiled to native ARM64 via IL2CPP |
| Anti-tamper | `libpglarmor.so` — signature check, memory integrity scan, root/debugger detection |
| Anti-cheat class | `AppGenuine` in `SYBO.Subway.Runtime.App.Genuine` |

The metadata is **unencrypted**. Il2CppDumper + `global-metadata.dat` + `libil2cpp.so` = full class/method/offset dump.

---

## 2. Frida Attach Notes

```
# Find process
frida-ps -U | grep -i subway
# → "Subway Surf"  (NOT "com.kiloo.subwaysurf")

# Attach by name
frida -U "Subway Surf" -l script.js

# Or by PID
frida -U -p 368 -l script.js
```

**Do not spawn** — `libil2cpp.so` only loads after Unity initialises. Attach to a running process that is already past the splash screen.

---

## 3. State Machine — Run Lifecycle

### Key assembly: `SYBO.Subway.State`
### Class: `RunnerStateMachine`

The game uses a state machine with these states (all confirmed in metadata):

| Class | Trigger | What it means |
|---|---|---|
| `RunnerStateMainMenu` | `Enter()` | Player is in lobby/menu |
| `RunnerStateEnterRun` | `Enter()` | Run is starting (route generation) |
| `RunnerStatePlaying` | `Enter()` | **Run is live — character is running** |
| `RunnerStateDead` | `Enter()` | **Character died** |
| `RunnerStateEndRun` | `Enter()` | End-of-run sequence starting |
| `RunnerStateRevive` | `Enter()` | Revive flow started |
| `RunnerStateReviveCountdown` | `Enter()` | Countdown before revive |
| `RunnerStateEmpty` | `Enter()` | Idle/uninitialized |
| `RunnerStateRouteGenerate` | `Enter()` | Procedural track being generated |
| `RunnerStatePauseCountdown` | `Enter()` | Pause countdown |
| `RunnerStateGetCurrencyPauseCountdown` | `Enter()` | "Get coins" pause |
| `RunnerStatePreLevelBooster` | `Enter()` | Pre-run booster selection |
| `RunnerStateBeingMoved` | `Enter()` | Character teleporting |

### Properties on `RunnerStateMachine`
```
get_IsPlaying       → bool   (true during active run)
get_IsRunning       → bool   (alias/backup)
set_IsPlaying       → fires when value changes  ← best hook target
set_IsRunning       → fires when value changes
```

**Hook strategy:** `set_IsPlaying` fires exactly when the game transitions in/out of a run. More reliable than `Enter()` methods on individual states.

### Backing fields (private)
```
<IsPlaying>k__BackingField
<IsRunning>k__BackingField
```

---

## 4. Character Input & Lane System

### Class: `CharacterInputController`
**Namespace:** `SYBO.RunnerCore.Character`  
**Source:** `Assets/SYBO/RunnerCore/Runtime/Character/CharacterInputController.cs`

```
get_CurrentLaneIndex    → int (0 = left, 1 = mid, 2 = right)
get_AllowInput          → bool
set_AllowInput          → enable/disable input
ProcessInput()          → called each frame to process queued input
HandleSwipe()           → entry point for swipe gesture
SetQueuedInput()        → queue a swipe for next frame processing
ProcessQueueInput()     → flush queued input
ClearQueuedInput()      → discard queued input
```

**Private fields:**
```
_currentLaneIndex
_queuedInput
_queuedInputTimer
MaximumInputQueueDuration
```

**Lane constants** (on `CharacterMotor`):
```
LeftLaneIndex   = 0
MidLaneIndex    = 1
RightLaneIndex  = 2
NumberOfLanes   = 3 (implied)
```

### Swipe Detection (`DetectSwipeWidget` / `StickySwipeWidget`)
```
_fastSwipeDistance      ← swipe detection threshold
_startSwipeTime         ← swipe timing start
_swipeThreshold         ← minimum swipe distance
_stickySwipeDistance    ← sticky swipe threshold
_cancelOtherInputsDistance
OnDetectSwipe           ← event fired on valid swipe
OnCancelSwipe           ← event fired on cancelled swipe
SwipeDirection          ← enum (Up/Down/Left/Right)
HandleSwipe()           ← processes detected swipe
```

### Lane Change System (`CharacterMotor`)
```
TargetLane              ← destination lane index
LaneChangeStarted       ← event
LaneChangeFinished      ← event
LaneChangeElapsedTime
LaneChangeSpeedModifier
LaneChangeXCurve
OnLaneChangeStarted     → delegate hook point
OnLaneChangeFinished    → delegate hook point
AbortLaneChange()
GetLaneChangeDuration()
ApplyLaneChangeVelocity()
```

---

## 5. Score System

### Class: `ScoreManager`
```
AddScore(int amount)        ← add to current score (multiply here for cheat)
SetScore(int value)         ← set score directly
SetScoreOverride(int value) ← override score
GetScore() → int
get_CurrentScore → int
set_Score
```

**Events:**
```
OnScoreAdded
OnScoreSubmitted
add_OnScoreAdded / remove_OnScoreAdded
```

**Backing fields:**
```
<CurrentScore>k__BackingField
<MinScoreValue>k__BackingField
```

**High score:**
```
HighScoreKeyFormat
IsNewHighScore          ← bool property
HadNewHighScoreThisRun  ← bool property
GetHighScore()
SetHighScore()
SubmitNewHighScores()
```

---

## 6. Score Multiplier System

### Class: `ScoreMultiplierManager`
```
AddScoreMultiplier(int tier)    ← push multiplier up (hook → always pass 10)
AddEventScoreMultiplier()
NotifyScoreMultiplierUpdated()
NotifyScoreMultiplierIncreased()
get_EventScoreMultiplier → int
set_EventScoreMultiplier
get_CurrentScoreMultiplier → int (read-only)
HighestScoreMultiplier
HighestScoreMultiplierInRun
CurrentScoreMultiplier
```

**Events:**
```
OnScoreMultiplierUpdated
OnScoreMultiplierIncreased
add_OnScoreMultiplierUpdated / remove_OnScoreMultiplierUpdated
```

**Backing fields:**
```
_eventScoreMultiplier
<IsPlaying>k__BackingField  (on RunnerStateMachine, not here)
```

---

## 7. Hoverboard System

### Class: `HoverboardSystem`
**Namespace:** `SYBO.Subway` / `SYBO.Subway.Systems`

```
get_HasHoverboard → bool        ← hook retval → return 1 = always has one
ActivateHoverboard()            ← call to activate programmatically
DeactivateHoverboard()
ConsumeHoverboard()             ← hook to swallow = never consumed
SetHoverboardState(bool active)
SetHoverboardActive(bool)
get_HoverboardActive → bool
get_CurrentHoverboard
ShowHoverboard()
HideHoverboard()
MainHoverboardSystem            ← singleton accessor
FetchHoverboardSystem()
```

**Related class: `RunBoardController`**
```
get_HoverboardActive
set_HoverboardActive
get_HoverboardController
```

---

## 8. Speed System

### Class: `SpeedController` / `DefaultSpeedController`
**Namespace:** `SYBO.Subway`  
**Source:** `Assets/SYBO/Subway/Runtime/Run/Stats/Speed/SpeedController.cs`

```
get_TimeScale → float
set_TimeScale(float)
SetTimeScale(float, key)
ChangeTimeScale()
GetTimeScale() → float
CalculateNewTimeScale() → float
```

**Time scale system** (`TimeScaleController`):
```
kTimeScaleMin
kTimeScaleMax
m_TimeScale
SetTimeScaleIndependent()
TimeScaleKey            ← string key for layered time scale
TimeScaleKeyComparer
```

**Character speed** (`CharacterSpeedConfig`):
```
SetSpeedConfig()
SetLaneSpeed()
CharacterSpeedConfigInstance
DefaultSpeedConfig
```

---

## 9. Powerup System

### Class: `PowerEffect` (base), concrete effects:

| Class | Effect |
|---|---|
| `JetpackPowerEffect` | Jetpack flight |
| `MagnetPowerEffect` | Coin magnet |
| `ShieldPowerEffect` | Shield (absorbs one hit) |
| `InvincibilityPowerEffect` | Brief invincibility |
| `HoverboardPowerEffect` | Hoverboard activation |
| `DoubleScorePowerEffect` | 2x score multiplier |
| `DoubleCoinsPowerEffect` | 2x coin pickup |
| `ScoreBoosterPowerEffect` | Score booster tier |
| `HeadStartPowerEffect` | Head start |
| `PogoStickPowerEffect` | Pogo stick |
| `SpeedPadPowerEffect` | Speed pad boost |
| `TeleportPowerEffect` | Teleport |
| `LowriderPowerEffect` | Low rider board |
| `GliderPowerEffect` | Glider |

**`PowerupEventController`** — handles all powerup pickup events:
```
HandleJetpackPickedUp()
HandleMagnetPickedUp()
HandleShieldPickedUp()
HandleHoverboardPickedUp()
HandleSuperSneakersPickedUp()
HandlePogoStickPickedUp()
HandleHeadStartPickedUp()
HandleMysteryPowerupPickedUp()
```

---

## 10. Track / Obstacle System

### Track generation: `QuickPlayChunkManager`
**Namespace:** `SYBO.RunnerCore.BuildingBlocks`  
**Source:** `Assets/SYBO/RunnerCore/Runtime/BuildingBlocks/QuickPlayChunkManager.cs`

```
GetNextChunkPrefab()
HasNextChunk() → bool
PrepareSection()
CleanupPassedChunks()
CleanAllChunks()
DespawnChunk()
PrintSpawnedSections()   ← debug — useful for understanding track layout
```

### Obstacle types (confirmed in metadata):
- `MovingTrain` — moving train obstacle
- `FallingTrain` — falling train
- `MovingBlocker` — generic moving blocker
- `DefaultMovingBlockerVisuals`
- `ChaseTargetMovingBlockerVisuals`
- `HurdleDefault` — standard hurdle/barrier
- `HurdleMalfunctioningVisual` — malfunctioning hurdle
- `SpeedPad` / `SpeedPadBoost` / `SpeedPadSlow`
- `TreadmillingState` — treadmill sections
- `FloorIsLavaFallingTrain` — lava floor variant
- `PlantInvasionFallingTrain` / `PlantInvasionMovingBlocker`

### Boundary/Lane system:
```
BoundarySlot            ← lane boundary slot
BoundarySlotStreak      ← streak of boundary obstacles
ChunkBoundarySlot
BoundarySlotAssetType   ← enum (Train, Fence, etc.)
IsChangingLaneTowardsBoundary() → bool
DisableBoundaryImpact   ← bool property
ForceBoundaryImpact()
```

---

## 11. Character Motor (`CharacterMotor`)
**Namespace:** `SYBO.RunnerCore.Character`

### Abilities attached:
```
JumpAbility     → JumpAbilityInstance    (handles jump)
RollAbility     → RollAbilityInstance    (handles roll/slide)
LaneChangeAbility → LaneChangeAbilityInstance
CollisionAbility
DangerousFloorAbility
MovementAbility
```

### States the motor tracks:
```
IdleState
RunningState
JumpingState
FallingState
RollingState
DivingState
FlyingState
TreadmillingState
ImpactFrameState
DeterministicJumpingState
CustomJumpingState
```

### Key config:
```
CharacterMotorConfig
CharacterSpeedConfig
CharacterSpeedConfigCollection
CustomJumpSettings
```

---

## 12. Input Pipeline (how swipes reach the character)

```
Touch screen
  → LeanTouch (CW/LeanTouch library)
    → DetectSwipeWidget / DetectStickySwipeWidget
      → OnDetectSwipe event fires with SwipeDirection
        → CharacterAbstractInputController.HandleSwipe()
          → CharacterInputController.SetQueuedInput()
            → CharacterMotor applies lane change / jump / roll
```

**To inject a fake swipe programmatically**, hook `SetQueuedInput` or call `HandleSwipe` directly via Frida.

**`InputSwipe`** (in `SYBO.Common.Input`):
```
CurrentSwipe    ← current swipe being processed
SwipeDirection  ← enum: Left, Right, Up, Down
```

---

## 13. Security / Anti-cheat (`AppGenuine`)

**Class:** `AppGenuine`  
**Namespace:** `SYBO.Subway.Runtime.App.Genuine`  
**Source:** `Assets/SYBO/Subway/Runtime/App/Genuine/AppGenuine.cs`

```
IsApplicationGenuine()          → bool — main integrity check
IsApplicationGenuineAvailable() → bool
GenuineStatus                   → enum
Genuine                         → bool property
SetGenuine()
GenuineApp                      → bool
UnityGenuineCheckFailed         ← event
```

**Bootstrap:** `BootstrapAppGenuineCheck` runs this at startup.

**pglarmor** (`libpglarmor.so`) operates at native level:
- APK signature verification
- Memory region integrity scan of `libil2cpp.so` text segment
- Root detection (`su` binary, Magisk paths)
- Debugger detection (ptrace, timing)

**Bypass approach:** Frida gadget injection (not external attach) avoids ptrace detection. Magisk module to patch pglarmor before it runs is the cleanest approach.

---

## 14. IL2CPP Method Resolution for Frida

### The actual hook target names

The IL2CPP registry stores **short class names** (no namespace). When iterating with `class_get_methods`, method names match the C# source names exactly:

```
Class name in registry      Full qualified name
─────────────────────────   ──────────────────────────────────────────
RunnerStateMachine          SYBO.Subway.State.RunnerStateMachine
RunnerStatePlaying          SYBO.Subway.State.RunnerStatePlaying
RunnerStateDead             SYBO.Subway.State.RunnerStateDead
RunnerStateEnterRun         SYBO.Subway.State.RunnerStateEnterRun
RunnerStateEndRun           SYBO.Subway.State.RunnerStateEndRun
CharacterInputController    SYBO.RunnerCore.Character.CharacterInputController
CharacterMotor              SYBO.RunnerCore.Character.CharacterMotor
ScoreManager                (Assembly-CSharp or SYBO.Subway assembly)
ScoreMultiplierManager      SYBO.Subway assembly
HoverboardSystem            SYBO.Subway assembly
SpeedController             SYBO.Subway assembly
```

### Why hooks were missing (diagnosed issue)

The Frida script was only scanning these assemblies:
```
Assembly-CSharp.dll
SYBO.RunnerCore.dll
SYBO.Subway.Core.dll
```

But the state machine classes live in whatever assembly IL2CPP compiled `SYBO.Subway.State.*` into — possibly `SYBO.Subway.dll` or merged into `Assembly-CSharp.dll`. The fix: scan **all non-Unity assemblies**.

### Correct scanning strategy
```javascript
// Skip Unity engine assemblies, scan everything else
if (imageName.startsWith("UnityEngine") || imageName.startsWith("Unity.")) continue;
// Scan all others
```

### Property getter/setter naming
C# properties compile to IL2CPP as:
- `get_IsPlaying` — getter (returns value)
- `set_IsPlaying` — setter (called when value assigned) ← better hook for change events
- `<IsPlaying>k__BackingField` — private backing storage

---

## 15. Key Analytics Events (useful for understanding game flow)

These fire at the right moments and can be hooked as state indicators:

```
Game_StateRewardMultiplied      ← run ended, multiplier applied
Game_NewHighScore               ← new high score achieved
Powerup_ActivateHoverboard      ← hoverboard activated
Motor_LaneChangeStarted         ← character begins lane change
Powerup_ShieldActivated         ← shield hit
Powerup_ShieldPointsSubmitted   ← shield used up
State_RunStatePlayEntered       ← run started (state event)
State_PlayerGetCurrencyPause    ← pause for currency
Game_CurrencyUpdated            ← coins/score changed
```

---

## 16. Source Tree Layout (from embedded file paths)

```
Assets/
  SYBO/
    RunnerCore/
      Runtime/
        BuildingBlocks/    ← chunk system, section configs, entity system
        Character/         ← CharacterMotor, CharacterInputController, abilities
        Entities/          ← entity type system
        Powers/            ← power configs and effects
          Default/
          Mystery/
          RaceMode/
          Specials/
          Upgrades/
    Subway/
      Runtime/
        App/               ← app lifecycle, networking, genuine check
          Genuine/         ← AppGenuine.cs
        Animation/         ← character animations, state machine behaviours
        Debug/             ← debug tools (DebugCoinDoubleEnabler, etc.)
        Meta/
          GameState/
            Rewards/       ← RewardsManager, handlers
        Mutators/          ← run mutators (powerup spawning, game modes)
        Pickups/           ← CoinPickup, SeasonTokenPickUp, magnetization
        Powers/            ← power effects (JetpackPowerEffect, etc.)
        Run/
          BuildingBlocks/  ← TrackController, HoverboardTutorialHandler
          Character/       ← Hoverboard.cs, effects
          Stats/
            Speed/         ← SpeedController.cs, DefaultSpeedController.cs
          StateMachineV2/  ← RunnerStateMachine.cs, all state classes
          TimeScale/       ← TimeScaleController.cs
        Score/             ← AddedScoreMultiplier, ItemScoreMultiplierMap
        Spawning/          ← spawners for coins, tokens, powerups
        Systems/
          Version2/
            Interfaces/    ← HoverboardSystem.cs, IPowerSystem.cs
        Tutorial/          ← tutorial steps for hoverboard, input
        VFX/               ← TrailSpeedController.cs
        UI/
          Slices/          ← all UI panels
          Widgets/         ← all UI widgets
```

---

## 17. Confirmed Hook Targets for Bot

In priority order:

### State detection (most reliable)
```javascript
// Definitive run start
hook("RunnerStatePlaying", "Enter")     → isPlaying = true
hook("RunnerStateEnterRun", "Enter")    → isPlaying = true (backup)

// Definitive death
hook("RunnerStateDead", "Enter")        → isPlaying = false

// Property change (fires on every transition)
hook("RunnerStateMachine", "set_IsPlaying")  → read args[1]
```

### Lane position (most reliable)
```javascript
hook("CharacterInputController", "get_CurrentLaneIndex")  → read retval
// Private field (if getter hook misses):
// _currentLaneIndex on CharacterInputController instance
```

### Score manipulation
```javascript
hook("ScoreManager", "AddScore")        → multiply args[1]
hook("ScoreManager", "SetScore")        → replace args[1]
hook("ScoreMultiplierManager", "AddScoreMultiplier")  → force args[1] = 10
```

### God mode (hoverboard never breaks)
```javascript
hook("HoverboardSystem", "get_HasHoverboard")   → retval.replace(ptr(1))
hook("HoverboardSystem", "ConsumeHoverboard")   → swallow (NOP)
```

### Speed cap
```javascript
hook("SpeedController", "set_TimeScale")  → clamp args[1]
// or
hook("CharacterInputController", "set_Speed")  → clamp args[1]
```

---

## 18. Notes on Version Compatibility

The metadata strings are consistent across versions unless SYBO renames classes. The classes most likely to survive updates intact:
- `RunnerStateMachine`, `RunnerStatePlaying`, `RunnerStateDead` — core state machine, very stable
- `CharacterInputController` — stable, it's the core input class
- `ScoreManager` — stable
- `HoverboardSystem` — stable

The classes most likely to change:
- `DefaultSpeedController` — speed management often refactored
- UI slices — renamed frequently with each season
- Analytics event names — change per update

When a hook misses, run the Frida script with the class-dump debug output enabled to see what names the runtime actually has.