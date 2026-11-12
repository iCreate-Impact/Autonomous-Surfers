/*
 * SubwayBot.cs  v2
 *
 * Fix: all pipe writes are serialized through a channel.
 * ConsoleInputLoop and BotLoop enqueue commands; the pipe
 * task drains the channel and writes — no thread contention.
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

    static ulong HvcPtrStart    = 0x0000018025E584F0UL;
    static ulong CeHva          = 0x0000000000000000UL;
    const  string PipeName      = "recon";
    const  int    ReconnectDelayMs  = 2000;
    const  int    SwipeCooldownMs   = 260;

    // ── state ─────────────────────────────────────────────────────────────────

    static volatile int  s_currentLane = 0;
    static volatile bool s_laneValid   = false;
    static volatile bool s_running     = true;
    static long          s_lastSwipeMs = 0;
    static ulong         s_hvaBase     = 0;

    // Single writer channel — only the pipe task reads from this.
    static readonly Channel<string> s_sendQueue =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false   // multiple threads enqueue
        });

    // ── entry point ───────────────────────────────────────────────────────────

    static async Task Main(string[] args)
    {
        Console.Title = "SubwayBot v2";
        Console.WriteLine("SubwayBot v2 — connecting to recon.dll pipe");
        Console.WriteLine("Commands: setgpa <hex>  |  read  |  swipe -1/0/1  |  ping  |  hvabase  |  quit");
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
    // All threads call this. Never touch s_writer directly.

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
                        ulong.TryParse(parts[i+1],
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

        // Start streaming
        Send("START");

        // Force an initial read
        Send("READ");

        // Writer task: drains the channel and flushes to the pipe
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
                    s_laneValid   = true;
                    s_currentLane = lane;
                    string name = lane switch { -1 => "LEFT", 0 => "CENTER", _ => "RIGHT" };
                    Console.WriteLine($"[bot]  LANE {lane,2}  ({name})");
                }
            }
            else if (line is "OK" or "PONG" || line.StartsWith("ERR"))
            {
                Console.WriteLine($"[pipe] {line}");
            }
            else if (line.StartsWith("STATUS"))
            {
                Console.WriteLine($"[recon] {line}");
            }
        }

        cts.Cancel();
        try { await writeTask; } catch { /* expected on cancel */ }
    }

    // ── bot logic ─────────────────────────────────────────────────────────────

    static void BotLoop()
    {
        while (s_running)
        {
            if (s_laneValid)
                BotDecideAndAct();
            Thread.Sleep(16);
        }
    }

    static void BotDecideAndAct()
    {
        int lane = s_currentLane;
        if (lane != 0)
            Swipe(0);
    }

    static void Swipe(int targetLane)
    {
        long now = Environment.TickCount64;
        if (now - s_lastSwipeMs < SwipeCooldownMs)
        {
            Console.WriteLine($"[bot]  swipe to {targetLane} suppressed (cooldown)");
            return;
        }
        s_lastSwipeMs = now;
        Send($"SWIPE {targetLane}");
        Console.WriteLine($"[bot]  SWIPE → {LaneName(targetLane)}");
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
                    Send($"SWIPE {lane}");
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
                Console.WriteLine("commands: setgpa <hex>  |  read  |  start  |  stop  |  ping  |  swipe -1/0/1  |  hvabase  |  quit");
            }
        }
    }
}