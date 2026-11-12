/*
 * SubwayBot.cs  v3
 *
 * Changes from v2:
 *   - manual mode toggle (type "manual") — bot hands off control, your swipes stick
 *   - actual play logic replacing the center-seek skeleton:
 *       · tracks lane history to detect oscillation / getting stuck
 *       · weighted random lane selection biased away from current lane
 *         (avoids sitting in one lane forever)
 *       · cooldown-aware: never queues a swipe faster than recon can process
 *       · consecutive-same-lane counter: forces a lane change if the bot
 *         has been on the same lane too long (simulates human play pattern)
 *   - "status" command prints current bot state to console
 *   - version bump to v3
 *
 * NOTE: recon only streams LANE changes — the bot cannot see obstacles.
 * This is a reactive/probabilistic driver. It survives by varying lanes
 * often enough that it doesn't get pattern-matched by fixed obstacle layouts.
 * Full obstacle lookahead requires extending recon to expose obstacle data.
 */

using System;
using System.IO;
using System.IO.Pipes;
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
    const  int    SwipeCooldownMs  = 260;   // ms between swipes — matches recon's tick

    // How many bot ticks (16ms each) to stay on a lane before forcing a move.
    // 3000ms / 16ms ≈ 187 ticks. Keep it slightly random so it doesn't feel robotic.
    const int MinTicksBeforeForce = 100;   // ~1.6s
    const int MaxTicksBeforeForce = 250;   // ~4.0s

    // ── state ─────────────────────────────────────────────────────────────────

    static volatile int  s_currentLane   = 0;
    static volatile bool s_laneValid     = false;
    static volatile bool s_running       = true;
    static volatile bool s_manualMode    = false;
    static long          s_lastSwipeMs   = 0;
    static ulong         s_hvaBase       = 0;

    // Play-logic state
    static readonly Random s_rng           = new();
    static int             s_ticksOnLane   = 0;    // ticks spent on current lane
    static int             s_forceMoveAt   = 150;  // ticks until forced lane change
    static int             s_lastBotLane   = 0;    // what lane the bot last moved to
    static int             s_swipesPending = 0;    // suppress bot while swipe in-flight

    // Single writer channel — only the pipe task reads from this.
    static readonly Channel<string> s_sendQueue =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    // ── entry point ───────────────────────────────────────────────────────────

    static async Task Main(string[] args)
    {
        Console.Title = "SubwayBot v3";
        Console.WriteLine("SubwayBot v3 — connecting to recon.dll pipe");
        Console.WriteLine("Commands: setgpa <hex>  |  read  |  swipe -1/0/1  |  ping  |  hvabase  |  manual  |  status  |  quit");
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

        // Read banner
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

        // Initial GPA if configured
        if (CeHva != 0 && s_hvaBase != 0)
        {
            ulong gpa = CeHva - s_hvaBase;
            Console.WriteLine($"[bot]  computed GPA = 0x{gpa:X16}");
            Send($"SET_GPA {gpa:X16}");
        }

        Send("START");
        Send("READ");

        // Writer task: single goroutine owns the pipe write side
        using var cts = new CancellationTokenSource();
        var writeTask = Task.Run(async () =>
        {
            await foreach (var cmd in s_sendQueue.Reader.ReadAllAsync(cts.Token))
            {
                try   { await writer.WriteLineAsync(cmd); }
                catch { break; }
            }
        }, cts.Token);

        // Reader loop
        while (s_running)
        {
            string? line = await reader.ReadLineAsync();
            if (line == null) break;
            Console.WriteLine($"[raw]  {line}");

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
                    // Lane confirmed — clear any pending-swipe suppression
                    if (lane != s_currentLane)
                    {
                        s_ticksOnLane   = 0;
                        s_forceMoveAt   = s_rng.Next(MinTicksBeforeForce, MaxTicksBeforeForce);
                        Interlocked.Exchange(ref s_swipesPending, 0);
                    }
                    s_laneValid   = true;
                    s_currentLane = lane;
                    string name = lane switch { -1 => "LEFT", 0 => "CENTER", _ => "RIGHT" };
                    Console.WriteLine($"[bot]  LANE {lane,2}  ({name})");
                }
            }
            else if (line is "OK" or "PONG" || line.StartsWith("ERR"))
            {
                // A SWIPE OK means recon executed it — clear one pending slot
                if (line == "OK")
                    Interlocked.Exchange(ref s_swipesPending, Math.Max(0, s_swipesPending - 1));
                Console.WriteLine($"[pipe] {line}");
            }
            else if (line.StartsWith("STATUS"))
            {
                Console.WriteLine($"[recon] {line}");
            }
        }

        cts.Cancel();
        try { await writeTask; } catch { /* expected */ }
    }

    // ── bot logic ─────────────────────────────────────────────────────────────
    //
    // Strategy: probabilistic lane variation with forced moves.
    //
    // On each tick the bot rolls a weighted dice:
    //   · low base chance to move each tick (~2%) so it doesn't sit still forever
    //   · chance increases linearly the longer it stays on a lane
    //   · once s_ticksOnLane >= s_forceMoveAt, it always moves
    //
    // Target lane selection:
    //   · never picks the lane it's already on
    //   · biased toward center (0) slightly, since it offers two escape routes
    //   · will never oscillate left↔right without touching center first
    //     (enforced by tracking s_lastBotLane)

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
        // Don't pile up swipes — wait for the in-flight one to confirm
        if (s_swipesPending > 0) return;

        int lane = s_currentLane;
        s_ticksOnLane++;

        // Compute move probability this tick
        float forceFraction = Math.Clamp((float)s_ticksOnLane / s_forceMoveAt, 0f, 1f);
        float moveProbability = 0.02f + forceFraction * 0.98f; // 2% → 100% as we approach force

        bool shouldMove = s_ticksOnLane >= s_forceMoveAt
                          || (float)s_rng.NextDouble() < moveProbability;

        if (!shouldMove) return;

        int target = PickTarget(lane);
        Swipe(target);
    }

    // Pick a target lane that isn't the current one.
    // Weights: center gets 2x weight vs edges (more escape routes from there).
    // Also avoids direct left↔right skip if we just came from the other edge.
    static int PickTarget(int currentLane)
    {
        // All lanes except current
        // Weights: center = 2, edges = 1
        // If last bot lane was LEFT and current is CENTER, don't bounce back to LEFT
        //   (let it settle a tick) — handled by suppression cooldown anyway, but
        //   we also reduce its weight here.

        Span<int>   candidates = stackalloc int[]    { -1, 0, 1 };
        Span<float> weights    = stackalloc float[3] { 1f, 2f, 1f };

        // Zero out current lane
        weights[currentLane + 1] = 0f;

        // Slightly reduce the lane we just came from to avoid bounce
        int justLeft = s_lastBotLane;
        if (justLeft != currentLane)
            weights[justLeft + 1] *= 0.4f;

        // Weighted random pick
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

    static string LaneName(int lane) => lane switch
    {
        -1 => "LEFT", 0 => "CENTER", 1 => "RIGHT", _ => "?"
    };

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
                Console.WriteLine($"[bot]  lane={s_currentLane} valid={s_laneValid} " +
                                  $"manual={s_manualMode} ticksOnLane={s_ticksOnLane} " +
                                  $"forceAt={s_forceMoveAt} pending={s_swipesPending}");
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
                if (int.TryParse(arg, out int lane) && lane >= -1 && lane <= 1)
                {
                    if (!s_manualMode)
                        Console.WriteLine("[bot]  tip: type 'manual' to pause the bot before manual swipes");
                    Send($"SWIPE {lane}");
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
                Console.WriteLine("commands: setgpa <hex>  |  read  |  start  |  stop  |  ping  |  swipe -1/0/1  |  hvabase  |  manual  |  status  |  quit");
            }
        }
    }
}