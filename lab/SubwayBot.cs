/*
 * SubwayBot.cs  v4
 *
 * Changes from v3:
 *   - obstacle lookahead engine replacing probabilistic lane variation:
 *       · sends SCAN to recon every ScanIntervalMs
 *       · parses OBSTACLE <lane> <zDelta> / CHUNKS_DONE responses
 *       · BotDecideAndAct picks the nearest unblocked adjacent lane
 *         when a dangerous entity is within DangerZThreshold units ahead
 *       · falls back to probabilistic variation when no obstacles seen
 *         (keeps the game feeling human between obstacle bursts)
 *   - "scan" console command: manual single scan + dump
 *   - "obstacles" console command: print current obstacle snapshot
 *   - version bump to v4
 *
 * Pipe protocol additions (recon v7+):
 *   Bot sends:  SCAN
 *   DLL sends:  OBSTACLE <lane> <zDelta>  (zero or more, nearest-first)
 *               CHUNKS_DONE
 *
 * Build: dotnet build -c Release
 * Run:   dotnet SubwayBot.dll
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

class SubwayBot
{
    // ── config ────────────────────────────────────────────────────────────────

    static ulong HvcPtrStart       = 0x0000018025E584F0UL;
    static ulong CeHva             = 0x0000000000000000UL;
    const  string PipeName         = "recon";
    const  int    ReconnectDelayMs = 2000;
    const  int    SwipeCooldownMs  = 260;    // ms between swipes — matches recon's tick

    // Probabilistic fallback (used when no obstacles detected).
    const int MinTicksBeforeForce = 100;    // ~1.6s
    const int MaxTicksBeforeForce = 250;    // ~4.0s

    // Obstacle lookahead tunables.
    const int   ScanIntervalMs   = 100;    // how often to send SCAN (~10Hz)
    const float DangerZThreshold = 60f;    // act when obstacle within this many Z units
    const float LookAheadZ       = 150f;   // ignore obstacles beyond this

    // ── state ─────────────────────────────────────────────────────────────────

    static volatile int  s_currentLane   = 0;
    static volatile bool s_laneValid     = false;
    static volatile bool s_running       = true;
    static volatile bool s_manualMode    = false;
    static long          s_lastSwipeMs   = 0;
    static ulong         s_hvaBase       = 0;

    // Probabilistic fallback state (unchanged from v3).
    static readonly Random s_rng           = new();
    static int             s_ticksOnLane   = 0;
    static int             s_forceMoveAt   = 150;
    static int             s_lastBotLane   = 0;
    static int             s_swipesPending = 0;

    // Obstacle snapshot — written by ReadLoop, read by BotLoop.
    static readonly object          s_obsLock      = new();
    static List<ObstacleInfo>       s_obstacles    = new();
    static DateTime                 s_lastScanSent = DateTime.MinValue;

    // Single writer channel.
    static readonly Channel<string> s_sendQueue =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    // ── entry point ───────────────────────────────────────────────────────────

    static async Task Main(string[] args)
    {
        Console.Title = "SubwayBot v4";
        Console.WriteLine("SubwayBot v4 — obstacle lookahead engine");
        Console.WriteLine("Commands: setgpa <hex>  |  read  |  scan  |  obstacles  |  swipe -1/0/1");
        Console.WriteLine("          ping  |  hvabase  |  manual  |  status  |  quit");
        Console.WriteLine(new string('─', 60));

        var inputThread = new Thread(ConsoleInputLoop) { IsBackground = true };
        inputThread.Start();

        var botThread = new Thread(BotLoop) { IsBackground = true };
        botThread.Start();

        while (s_running)
        {
            try   { await ConnectAndRunAsync(); }
            catch (Exception ex) { Console.WriteLine($"[pipe] error: {ex.Message}"); }

            if (s_running)
            {
                Console.WriteLine($"[pipe] disconnected — retrying in {ReconnectDelayMs}ms...");
                await Task.Delay(ReconnectDelayMs);
            }
        }
    }

    // ── send helper ───────────────────────────────────────────────────────────

    static void Send(string cmd) => s_sendQueue.Writer.TryWrite(cmd);

    // ── pipe session ──────────────────────────────────────────────────────────

    static async Task ConnectAndRunAsync()
    {
        using var pipe = new NamedPipeClientStream(
            ".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        Console.WriteLine("[pipe] connecting...");
        await pipe.ConnectAsync(5000);
        Console.WriteLine("[pipe] connected");

        using var reader = new StreamReader(pipe, leaveOpen: true);
        using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };

        // Read banner.
        string? banner = await reader.ReadLineAsync();
        if (banner != null)
        {
            Console.WriteLine($"[recon] {banner}");
            if (banner.Contains("HVA_BASE"))
            {
                var parts = banner.Split(' ');
                for (int i = 0; i < parts.Length - 1; i++)
                    if (parts[i] == "HVA_BASE" &&
                        ulong.TryParse(parts[i + 1],
                            System.Globalization.NumberStyles.HexNumber,
                            null, out ulong hva))
                    {
                        s_hvaBase = hva;
                        Console.WriteLine($"[bot]  HVA_BASE: 0x{hva:X16}");
                        Console.WriteLine($"[bot]  GPA = CE_HVA - 0x{hva:X16}");
                    }
            }
        }

        // Initial GPA if configured.
        if (CeHva != 0 && s_hvaBase != 0)
        {
            ulong gpa = CeHva - s_hvaBase;
            Console.WriteLine($"[bot]  computed GPA = 0x{gpa:X16}");
            Send($"SET_GPA {gpa:X16}");
        }

        Send("START");
        Send("READ");

        // Single writer task.
        using var cts = new CancellationTokenSource();
        var writeTask = Task.Run(async () =>
        {
            await foreach (var cmd in s_sendQueue.Reader.ReadAllAsync(cts.Token))
            {
                try   { await writer.WriteLineAsync(cmd); }
                catch { break; }
            }
        }, cts.Token);

        // Obstacle accumulator for one SCAN batch.
        var pendingObs = new List<ObstacleInfo>();

        // Reader loop.
        while (s_running)
        {
            string? line = await reader.ReadLineAsync();
            if (line == null) break;

            if (line.StartsWith("LANE "))
            {
                string val = line[5..];
                if (val == "?")
                {
                    s_laneValid = false;
                    Console.WriteLine("[bot]  LANE ? — GPA stale, send SET_GPA");
                }
                else if (int.TryParse(val, out int lane))
                {
                    if (lane != s_currentLane)
                    {
                        s_ticksOnLane  = 0;
                        s_forceMoveAt  = s_rng.Next(MinTicksBeforeForce, MaxTicksBeforeForce);
                        Interlocked.Exchange(ref s_swipesPending, 0);
                    }
                    s_laneValid   = true;
                    s_currentLane = lane;
                    Console.WriteLine($"[bot]  LANE {lane,2}  ({LaneName(lane)})");
                }
            }
            else if (line.StartsWith("OBSTACLE "))
            {
                // OBSTACLE <lane> <zDelta>
                var parts = line.Split(' ');
                if (parts.Length == 3
                    && int.TryParse(parts[1], out int ol)
                    && float.TryParse(parts[2],
                           System.Globalization.NumberStyles.Float,
                           System.Globalization.CultureInfo.InvariantCulture,
                           out float oz)
                    && oz <= LookAheadZ)
                {
                    pendingObs.Add(new ObstacleInfo(ol, oz));
                }
            }
            else if (line == "CHUNKS_DONE")
            {
                lock (s_obsLock)
                {
                    s_obstacles = new List<ObstacleInfo>(pendingObs);
                }
                pendingObs.Clear();

                // Log only when there's something to report.
                if (s_obstacles.Count > 0)
                {
                    Console.Write($"[obs]  {s_obstacles.Count} obstacle(s): ");
                    Console.WriteLine(string.Join("  ",
                        s_obstacles.Select(o => $"{LaneName(o.Lane)}@Z+{o.ZDelta:F0}")));
                }
            }
            else if (line is "OK" or "PONG" || line.StartsWith("ERR"))
            {
                if (line == "OK")
                    Interlocked.Exchange(ref s_swipesPending,
                        Math.Max(0, s_swipesPending - 1));
                // Suppress noisy OK/PONG chatter; uncomment to debug:
                // Console.WriteLine($"[pipe] {line}");
            }
            else if (line.StartsWith("STATUS"))
            {
                Console.WriteLine($"[recon] {line}");
            }
            else
            {
                Console.WriteLine($"[raw]  {line}");
            }
        }

        cts.Cancel();
        try { await writeTask; } catch { /* expected */ }
    }

    // ── bot loop ──────────────────────────────────────────────────────────────

    static void BotLoop()
    {
        while (s_running)
        {
            if (s_laneValid && !s_manualMode)
                BotDecideAndAct();
            Thread.Sleep(16);
        }
    }

    static void BotDecideAndAct()
    {
        if (s_swipesPending > 0) return;

        int lane = s_currentLane;
        s_ticksOnLane++;

        // ── throttle SCAN sends ──────────────────────────────────────────────
        var now = DateTime.UtcNow;
        if ((now - s_lastScanSent).TotalMilliseconds >= ScanIntervalMs)
        {
            Send("SCAN");
            s_lastScanSent = now;
        }

        // ── lookahead decision ───────────────────────────────────────────────
        List<ObstacleInfo> obs;
        lock (s_obsLock) { obs = s_obstacles; }

        // Find the nearest dangerous obstacle in the current lane.
        var threat = obs
            .Where(o => o.Lane == lane && o.ZDelta <= DangerZThreshold)
            .OrderBy(o => o.ZDelta)
            .FirstOrDefault();

        if (threat != null)
        {
            int target = PickEscapeLane(lane, obs);
            if (target != lane)
            {
                Console.WriteLine(
                    $"[bot]  OBSTACLE {LaneName(lane)} Z+{threat.ZDelta:F0}" +
                    $" → swipe {LaneName(target)}");
                Swipe(target);
                return;
            }
            // Both adjacent lanes also blocked — log it and fall through to
            // probabilistic; at least we'll be moving.
            Console.WriteLine(
                $"[bot]  all lanes blocked near Z+{threat.ZDelta:F0}, random move");
        }

        // ── probabilistic fallback (unchanged from v3) ───────────────────────
        float forceFraction    = Math.Clamp((float)s_ticksOnLane / s_forceMoveAt, 0f, 1f);
        float moveProbability  = 0.02f + forceFraction * 0.98f;
        bool  shouldMove       = s_ticksOnLane >= s_forceMoveAt
                                 || (float)s_rng.NextDouble() < moveProbability;
        if (!shouldMove) return;

        int probTarget = PickTarget(lane);
        Swipe(probTarget);
    }

    // ── lane pickers ──────────────────────────────────────────────────────────

    // Lookahead: pick the safest adjacent lane.
    // Score = sum of (LookAheadZ - zDelta) for obstacles in that lane —
    // lower total = safer.  Returns current lane if no better option.
    static int PickEscapeLane(int current, List<ObstacleInfo> obs)
    {
        int[] candidates = current switch {
            -1 => new[] { 0 },
            0  => new[] { -1, 1 },
            1  => new[] { 0 },
            _  => Array.Empty<int>()
        };

        int   bestLane  = current;
        float bestScore = float.MaxValue;

        foreach (int candidate in candidates)
        {
            float score = obs
                .Where(o => o.Lane == candidate && o.ZDelta <= LookAheadZ)
                .Sum(o => LookAheadZ - o.ZDelta);  // near obstacles score higher

            if (score < bestScore)
            {
                bestScore = score;
                bestLane  = candidate;
            }
        }

        return bestLane;
    }

    // Probabilistic: weighted random, biased toward center, no immediate bounce.
    static int PickTarget(int currentLane)
    {
        Span<int>   candidates = stackalloc int[]    { -1, 0, 1 };
        Span<float> weights    = stackalloc float[3] { 1f, 2f, 1f };

        weights[currentLane + 1] = 0f;

        int justLeft = s_lastBotLane;
        if (justLeft != currentLane)
            weights[justLeft + 1] *= 0.4f;

        float total = weights[0] + weights[1] + weights[2];
        float roll  = (float)s_rng.NextDouble() * total;
        float acc   = 0f;
        int   pick  = 0;
        for (int i = 0; i < 3; i++)
        {
            acc += weights[i];
            if (roll < acc) { pick = candidates[i]; break; }
        }

        return pick;
    }

    // ── swipe ─────────────────────────────────────────────────────────────────

    static void Swipe(int targetLane)
    {
        long now = Environment.TickCount64;
        if (now - s_lastSwipeMs < SwipeCooldownMs) return;

        s_lastSwipeMs = now;
        s_lastBotLane = s_currentLane;
        Interlocked.Increment(ref s_swipesPending);
        Send($"SWIPE {targetLane}");
        Console.WriteLine($"[bot]  SWIPE → {LaneName(targetLane)}  (ticks on lane: {s_ticksOnLane})");
        s_ticksOnLane = 0;
    }

    // ── console input ─────────────────────────────────────────────────────────

    static void ConsoleInputLoop()
    {
        while (s_running)
        {
            string? line = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(line)) continue;

            if (line is "quit" or "exit")
            {
                s_running = false;
                return;
            }
            else if (line == "manual")
            {
                s_manualMode = !s_manualMode;
                Console.WriteLine($"[bot]  manual mode {(s_manualMode ? "ON — bot paused" : "OFF — bot active")}");
            }
            else if (line == "status")
            {
                List<ObstacleInfo> snap;
                lock (s_obsLock) { snap = s_obstacles; }
                Console.WriteLine(
                    $"[bot]  lane={s_currentLane} valid={s_laneValid} " +
                    $"manual={s_manualMode} ticksOnLane={s_ticksOnLane} " +
                    $"forceAt={s_forceMoveAt} pending={s_swipesPending} " +
                    $"obstacles={snap.Count}");
            }
            else if (line == "scan")
            {
                Console.WriteLine("[cmd]  sending SCAN...");
                Send("SCAN");
            }
            else if (line == "obstacles")
            {
                List<ObstacleInfo> snap;
                lock (s_obsLock) { snap = s_obstacles; }
                if (snap.Count == 0)
                    Console.WriteLine("[obs]  no obstacles in snapshot");
                else
                    foreach (var o in snap.OrderBy(o => o.ZDelta))
                        Console.WriteLine($"  lane={LaneName(o.Lane)}  Z+{o.ZDelta:F1}");
            }
            else if (line == "read")  { Send("READ"); }
            else if (line == "ping")  { Send("PING"); }
            else if (line == "start") { Send("START"); }
            else if (line == "stop")  { Send("STOP"); }
            else if (line == "hvabase")
            {
                Console.WriteLine($"[bot]  HVA_BASE = 0x{s_hvaBase:X16}");
            }
            else if (line.StartsWith("swipe "))
            {
                string arg = line[6..].Trim();
                if (int.TryParse(arg, out int swipeLane) && swipeLane >= -1 && swipeLane <= 1)
                {
                    if (!s_manualMode)
                        Console.WriteLine("[bot]  tip: type 'manual' to pause the bot before manual swipes");
                    Send($"SWIPE {swipeLane}");
                }
                else
                    Console.WriteLine("usage: swipe -1 | 0 | 1");
            }
            else if (line.StartsWith("setgpa "))
            {
                string hexPart = line[7..].Trim();
                if (hexPart.Length > 10 && s_hvaBase != 0 &&
                    ulong.TryParse(hexPart,
                        System.Globalization.NumberStyles.HexNumber,
                        null, out ulong ceHva))
                {
                    ulong gpa = ceHva - s_hvaBase;
                    Console.WriteLine($"[bot]  CE_HVA 0x{ceHva:X} - HVA_BASE 0x{s_hvaBase:X} = GPA 0x{gpa:X}");
                    Send($"SET_GPA {gpa:X16}");
                }
                else
                {
                    Send($"SET_GPA {hexPart.ToUpperInvariant()}");
                }
            }
            else
            {
                Console.WriteLine(
                    "commands: setgpa <hex>  |  read  |  scan  |  obstacles  |  start  |  stop" +
                    "  |  ping  |  swipe -1/0/1  |  hvabase  |  manual  |  status  |  quit");
            }
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    static string LaneName(int lane) => lane switch
    {
        -1 => "LEFT", 0 => "CENTER", 1 => "RIGHT", _ => "?"
    };

    // ── types ─────────────────────────────────────────────────────────────────

    record ObstacleInfo(int Lane, float ZDelta);
}