/*
 * SubwayBot.cs  v1
 *
 * Visual Studio control plane for the Subway Surfers bot.
 * Connects to recon.dll v12 via \\.\pipe\recon and drives
 * all bot logic from here — no reinjection needed between runs.
 *
 * Usage:
 *   1. Build as a .NET 6+ Console App (x64).
 *   2. Inject recon.dll into HD-Player.exe once per BlueStacks session.
 *   3. Run SubwayBot.exe. It reconnects automatically on disconnect.
 *
 * To update bot logic: edit this file, rebuild, re-run. BlueStacks untouched.
 *
 * To set a fresh GPA mid-session (after CE gives you a new address):
 *   - Either type it at the console prompt, or
 *   - Hardcode it in MANUAL_GPA below (0 = let recon auto-discover).
 *
 * Project setup (Visual Studio):
 *   File > New > Project > Console App (.NET 6+)
 *   Replace Program.cs contents with this file.
 *   Build > Configuration Manager > x64
 */

using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

class SubwayBot
{
    // ── config ────────────────────────────────────────────────────────────────

    // HCPtrStart from the current session's Stage 2 log.
    // Update this after every BlueStacks restart.
    // The bot will print it from the STATUS banner automatically — just paste it here.
    static ulong HvcPtrStart = 0x0000018025E584F0UL;

    // CE address of the lane field (from Cheat Engine this session).
    // Set to 0 to rely on recon's auto-discovery.
    // If non-zero, SubwayBot computes GPA = CE_HVA - HvcPtrStart and sends SET_GPA.
    static ulong CeHva = 0x0000000000000000UL;

    // Pipe name — must match PIPE_NAME in recon_v12.cpp
    const string PipeName = "recon";

    // How long to wait between reconnect attempts (ms)
    const int ReconnectDelayMs = 2000;

    // ── state ─────────────────────────────────────────────────────────────────

    static volatile int   s_currentLane = 0;   // -1 LEFT  0 CENTER  1 RIGHT
    static volatile bool  s_laneValid   = false;
    static volatile bool  s_running     = true;
    static long           s_lastSwipeMs = 0;
    const int            SwipeCooldownMs = 260;

    // ── entry point ───────────────────────────────────────────────────────────

    static async Task Main(string[] args)
    {
        Console.Title = "SubwayBot v1";
        Console.WriteLine("SubwayBot v1 — connecting to recon.dll pipe");
        Console.WriteLine("Commands: setgpa <hex>  |  read  |  quit");
        Console.WriteLine(new string('─', 60));

        // Console input thread — lets you type commands while bot runs
        var inputThread = new Thread(ConsoleInputLoop) { IsBackground = true };
        inputThread.Start();

        // Bot logic thread
        var botThread = new Thread(BotLoop) { IsBackground = true };
        botThread.Start();

        // Main thread: pipe connection loop — reconnects on disconnect
        while (s_running)
        {
            try
            {
                await ConnectAndRunAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[pipe] error: {ex.Message}");
            }

            if (s_running)
            {
                Console.WriteLine($"[pipe] disconnected — retrying in {ReconnectDelayMs}ms...");
                await Task.Delay(ReconnectDelayMs);
            }
        }
    }

    // ── pipe session ──────────────────────────────────────────────────────────

    static StreamWriter? s_writer;
    static ulong         s_hvaBase = 0;

    static async Task ConnectAndRunAsync()
    {
        using var pipe = new NamedPipeClientStream(
            ".", PipeName, PipeDirection.InOut,
            PipeOptions.None);

        Console.WriteLine("[pipe] connecting...");
        await pipe.ConnectAsync(5000); // 5s timeout
        Console.WriteLine("[pipe] connected");

        using var reader = new StreamReader(pipe, leaveOpen: true);
        using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        s_writer = writer;

        // Read banner
        string? banner = await reader.ReadLineAsync();
        if (banner != null)
        {
            Console.WriteLine($"[recon] {banner}");
            // Parse HVA_BASE from banner: "STATUS READY HVA_BASE <hex>"
            if (banner.Contains("HVA_BASE"))
            {
                var parts = banner.Split(' ');
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    if (parts[i] == "HVA_BASE" && ulong.TryParse(parts[i+1],
                        System.Globalization.NumberStyles.HexNumber, null, out ulong hva))
                    {
                        s_hvaBase = hva;
                        Console.WriteLine($"[bot]  HVA_BASE this session: 0x{hva:X16}");
                        Console.WriteLine($"[bot]  GPA formula: GPA = CE_HVA - 0x{hva:X16}");
                    }
                }
            }
        }

        // If a CE address is configured, compute and send GPA now
        if (CeHva != 0 && s_hvaBase != 0)
        {
            ulong gpa = CeHva - s_hvaBase;
            Console.WriteLine($"[bot]  computed GPA = 0x{gpa:X16}  (CE_HVA 0x{CeHva:X16} - HVA_BASE 0x{s_hvaBase:X16})");
            await writer.WriteLineAsync($"SET_GPA {gpa:X16}");
            string? ack = await reader.ReadLineAsync();
            Console.WriteLine($"[pipe] SET_GPA ack: {ack}");
        }

        // Start streaming
        await writer.WriteLineAsync("START");
        string? startAck = await reader.ReadLineAsync();
        Console.WriteLine($"[pipe] START ack: {startAck}");

        // Read stream
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
                    Console.WriteLine("[bot]  LANE ? — GPA stale, send SET_GPA with fresh CE address");
                }
                else if (int.TryParse(val, out int lane))
                {
                    s_laneValid   = true;
                    s_currentLane = lane;
                    string name = lane == -1 ? "LEFT" : lane == 0 ? "CENTER" : "RIGHT";
                    Console.WriteLine($"[bot]  LANE {lane,2}  ({name})");
                }
            }
            else if (line == "OK" || line == "PONG" || line.StartsWith("ERR"))
            {
                // Ack from a mid-stream command (SET_GPA, PING, etc.)
                Console.WriteLine($"[pipe] {line}");
            }
            else if (line.StartsWith("STATUS"))
            {
                Console.WriteLine($"[recon] {line}");
            }
        }

        s_writer = null;
    }

    // ── bot logic ─────────────────────────────────────────────────────────────
    //
    // This is where you implement actual avoidance / decisions.
    // Right now it's a skeleton — it just prints what it would do.
    // Replace the Console.WriteLine calls with real input injection
    // (ADB swipe, BlueStacks key send, whatever you're using).

    static void BotLoop()
    {
        int prevLane = 999;
        while (s_running)
        {
            if (s_laneValid)
            {
                int lane = s_currentLane;
                if (lane != prevLane)
                {
                    BotReact(lane);
                    prevLane = lane;
                }
            }
            Thread.Sleep(16);
        }
    }

    static void BotReact(int lane)
    {
        // lane is TargetLane — where the player is moving TO.
        // Phase 1: just steer back to center whenever they drift.
        int target = DecideTarget(lane);
        if (target != lane)
            Swipe(target);
    }

    static int DecideTarget(int currentLane)
    {
        if (currentLane == 0) return 0;
        return 0;
    }

    static void Swipe(int targetLane)
    {
        long now = Environment.TickCount64;
        if (now - s_lastSwipeMs < SwipeCooldownMs)
        {
            Console.WriteLine($"[bot]  swipe to {targetLane} suppressed (cooldown)");
            return;
        }

        var w = s_writer;
        if (w == null)
        {
            Console.WriteLine("[bot]  swipe skipped (pipe not connected)");
            return;
        }

        w.WriteLine($"SWIPE {targetLane}");
        s_lastSwipeMs = now;
        Console.WriteLine($"[bot]  SWIPE → {LaneName(targetLane)}");
    }

    static string LaneName(int lane) => lane switch
    {
        -1 => "LEFT",
         0 => "CENTER",
         1 => "RIGHT",
         _ => "?"
    };

    // ── console input ─────────────────────────────────────────────────────────

    static void ConsoleInputLoop()
    {
        while (s_running)
        {
            string? line = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(line)) continue;

            if (line == "quit" || line == "exit")
            {
                s_running = false;
                return;
            }
            else if (line == "read")
            {
                s_writer?.WriteLine("READ");
            }
            else if (line == "ping")
            {
                s_writer?.WriteLine("PING");
            }
            else if (line.StartsWith("swipe "))
            {
                string arg = line[6..].Trim();
                if (int.TryParse(arg, out int lane) && lane >= -1 && lane <= 1)
                    s_writer?.WriteLine($"SWIPE {lane}");
                else
                    Console.WriteLine("usage: swipe -1 | 0 | 1");
            }
            else if (line.StartsWith("setgpa "))
            {
                // e.g. "setgpa AF3259AC"  or compute it yourself:
                // "setgpa" then paste CE_HVA - HVA_BASE result
                string hexPart = line[7..].Trim();

                // If user typed a full CE HVA, compute GPA automatically
                if (hexPart.Length > 10 && s_hvaBase != 0 &&
                    ulong.TryParse(hexPart,
                        System.Globalization.NumberStyles.HexNumber, null, out ulong ceHva))
                {
                    ulong gpa = ceHva - s_hvaBase;
                    Console.WriteLine($"[bot]  CE_HVA 0x{ceHva:X} - HVA_BASE 0x{s_hvaBase:X} = GPA 0x{gpa:X}");
                    s_writer?.WriteLine($"SET_GPA {gpa:X16}");
                }
                else
                {
                    // Treat it as a raw GPA
                    s_writer?.WriteLine($"SET_GPA {hexPart.ToUpperInvariant()}");
                }
            }
            else if (line == "stop")
            {
                s_writer?.WriteLine("STOP");
            }
            else if (line == "start")
            {
                s_writer?.WriteLine("START");
            }
            else if (line == "ping")
            {
                s_writer?.WriteLine("PING");
            }
            else if (line == "hvabase")
            {
                Console.WriteLine($"[bot]  HVA_BASE = 0x{s_hvaBase:X16}");
            }
            else
            {
                Console.WriteLine("commands: setgpa <hex>  |  read  |  start  |  stop  |  ping  |  hvabase  |  quit");
            }
        }
    }
}