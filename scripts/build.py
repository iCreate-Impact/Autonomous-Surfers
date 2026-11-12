"""
build.py — Autonomous Subway Surfers bot build script
Place in: X:/Github/Autonomous Subway/scripts/build.py

Usage:
  python build.py          build both
  python build.py recon    build only recon.dll
  python build.py bot      build only SubwayBot
  python build.py run      build both, then launch SubwayBot.exe
"""

import sys
import os
import subprocess
import shutil
from pathlib import Path

# ── paths ─────────────────────────────────────────────────────────────────────

SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT        = SCRIPTS_DIR.parent
LAB         = ROOT / "lab"

RECON_SRC   = LAB / "recon.cpp"
RECON_DLL   = LAB / "recon.dll"
RECON_OBJ   = LAB / "recon.obj"

BOT_DIR     = LAB / "SubwayBot"
BOT_EXE     = BOT_DIR / "bin" / "x64" / "Release" / "net8.0" / "SubwayBot.exe"
# fallback if csproj writes to the other path
BOT_EXE_ALT = BOT_DIR / "bin" / "Release" / "net8.0" / "SubwayBot.exe"

# ── args ──────────────────────────────────────────────────────────────────────

arg       = sys.argv[1].lower() if len(sys.argv) > 1 else "both"
do_recon  = arg in ("both", "recon", "run")
do_bot    = arg in ("both", "bot", "run")
do_run    = arg == "run"

print()
print(" Autonomous Subway Bot — build script (python)")
print(f" Root : {ROOT}")
print(f" Lab  : {LAB}")
print()

recon_ok = False
bot_ok   = False

# ── build recon.dll ───────────────────────────────────────────────────────────

if do_recon:
    import winreg

    def find_vswhere():
        for base in (
            os.environ.get("ProgramFiles(x86)", ""),
            os.environ.get("ProgramFiles", ""),
        ):
            p = Path(base) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
            if p.exists():
                return p
        return None

    def find_vcvars():
        vswhere = find_vswhere()
        if not vswhere:
            print("[recon] ERROR: vswhere.exe not found")
            return None
        result = subprocess.run(
            [str(vswhere), "-latest", "-products", "*",
             "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-property", "installationPath"],
            capture_output=True, text=True
        )
        vs_path = result.stdout.strip()
        if not vs_path:
            print("[recon] ERROR: no VS installation with VC++ tools found")
            return None
        vcvars = Path(vs_path) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
        if not vcvars.exists():
            print(f"[recon] ERROR: vcvars64.bat not found at {vcvars}")
            return None
        print(f"[recon] using VS at: {vs_path}")
        return vcvars

    print("[recon] locating MSVC ...")
    vcvars = find_vcvars()

    if not vcvars:
        recon_ok = False
    else:
        print("[recon] compiling recon.cpp ...")
        # run cl inside a vcvars64 environment
        cmd = (
            f'call "{vcvars}" >nul 2>&1 && '
            f'cl /LD /O2 /EHsc "{RECON_SRC}" '
            f'/Fe:"{RECON_DLL}" /Fo:"{RECON_OBJ}" '
            f'/link /DLL psapi.lib /OUT:"{RECON_DLL}"'
        )
        result = subprocess.run(cmd, shell=True, cwd=str(LAB))
        if result.returncode != 0:
            print("[recon] BUILD FAILED")
            recon_ok = False
        else:
            print(f"[recon] OK — {RECON_DLL}")
            recon_ok = True

# ── build SubwayBot ───────────────────────────────────────────────────────────

if do_bot:
    print("[bot] building SubwayBot (.NET 8, x64) ...")

    result = subprocess.run(
        ["dotnet", "build", "-c", "Release", "--no-incremental", "--nologo"],
        cwd=str(BOT_DIR)
    )

    if result.returncode != 0:
        print("[bot] BUILD FAILED")
        bot_ok = False
    else:
        # find wherever dotnet actually put the exe
        exe = BOT_EXE if BOT_EXE.exists() else BOT_EXE_ALT if BOT_EXE_ALT.exists() else None
        if exe:
            print(f"[bot] OK — {exe}")
            BOT_EXE_FINAL = exe
        else:
            # search for it
            matches = list(BOT_DIR.rglob("SubwayBot.exe"))
            if matches:
                BOT_EXE_FINAL = max(matches, key=lambda p: p.stat().st_mtime)
                print(f"[bot] OK — {BOT_EXE_FINAL}")
            else:
                print("[bot] WARNING: build succeeded but SubwayBot.exe not found")
                BOT_EXE_FINAL = None
        bot_ok = True

# ── summary ───────────────────────────────────────────────────────────────────

print()
print("─" * 45)
if do_recon:
    print(f"  recon.dll   {'OK' if recon_ok else 'FAILED'}")
if do_bot:
    print(f"  SubwayBot   {'OK' if bot_ok else 'FAILED'}")
print("─" * 45)
print()

# ── launch ────────────────────────────────────────────────────────────────────

if do_run:
    if not bot_ok:
        print("[run] skipping launch — SubwayBot build failed")
    elif BOT_EXE_FINAL:
        print(f"[run] launching {BOT_EXE_FINAL} ...")
        subprocess.Popen([str(BOT_EXE_FINAL)])
    else:
        print("[run] skipping launch — exe not found")