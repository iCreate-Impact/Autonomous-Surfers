@echo off
:: build.bat — Autonomous Subway Surfers bot build script
:: Place in:  X:\Github\Autonomous Subway\scripts\build.bat
:: Builds:    lab\recon.dll   (C++ x64, MSVC)
::            lab\SubwayBot\  (.NET 8, x64)
::
:: Run from anywhere — script resolves its own location.
:: Usage:
::   build.bat          build both
::   build.bat recon    build only recon.dll
::   build.bat bot      build only SubwayBot
::   build.bat run      build both, then launch SubwayBot.exe

setlocal EnableDelayedExpansion

:: ── resolve paths ─────────────────────────────────────────────────────────────

set "SCRIPTS_DIR=%~dp0"
:: scripts\ is one level above lab\, so go up one
for %%I in ("%SCRIPTS_DIR%..") do set "ROOT=%%~fI"
set "LAB=%ROOT%\lab"
set "RECON_SRC=%LAB%\recon.cpp"
set "RECON_DLL=%LAB%\recon.dll"
set "BOT_DIR=%LAB%\SubwayBot"
set "BOT_EXE=%BOT_DIR%\bin\x64\Release\net8.0\SubwayBot.exe"
set "BOT_SRC=%LAB%\SubwayBot.cs"
set "BOT_PROG=%BOT_DIR%\Program.cs"

echo.
echo  Autonomous Subway Bot — build script
echo  Root : %ROOT%
echo  Lab  : %LAB%
echo.

:: ── argument parsing ──────────────────────────────────────────────────────────

set "DO_RECON=1"
set "DO_BOT=1"
set "DO_RUN=0"

if /i "%~1"=="recon" ( set "DO_BOT=0" )
if /i "%~1"=="bot"   ( set "DO_RECON=0" )
if /i "%~1"=="run"   ( set "DO_RUN=1" )

:: ── locate MSVC cl.exe via vswhere ───────────────────────────────────────────

if "%DO_RECON%"=="1" (
    echo [recon] locating MSVC ...

    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "!VSWHERE!" (
        set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
    )

    if not exist "!VSWHERE!" (
        echo [recon] ERROR: vswhere.exe not found. Install Visual Studio Build Tools.
        goto recon_failed
    )

    :: Get the VS install path
    for /f "usebackq tokens=*" %%I in (
        `"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`
    ) do set "VS_PATH=%%I"

    if not defined VS_PATH (
        echo [recon] ERROR: No VS installation with VC++ tools found.
        goto recon_failed
    )

    :: Source vcvars64 to set up the x64 native tools environment
    set "VCVARS=!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"
    if not exist "!VCVARS!" (
        echo [recon] ERROR: vcvars64.bat not found at !VCVARS!
        goto recon_failed
    )

    echo [recon] using VS at: !VS_PATH!
    echo [recon] compiling recon.cpp ...

    :: Run cl inside a cmd /k vcvars64 environment
    cmd /c "call "!VCVARS!" >nul 2>&1 && cl /LD /O2 /EHsc "%RECON_SRC%" /Fe:"%RECON_DLL%" /Fo:"%LAB%\recon.obj" /link /DLL psapi.lib /OUT:"%RECON_DLL%""

    if errorlevel 1 (
        echo [recon] BUILD FAILED
        goto recon_failed
    )

    echo [recon] OK — %RECON_DLL%
    goto recon_done
)
:recon_failed
set "RECON_OK=0"
goto bot_step
:recon_done
set "RECON_OK=1"

:: ── build SubwayBot ───────────────────────────────────────────────────────────

:bot_step
if "%DO_BOT%"=="0" goto summary

echo.
echo [bot] syncing SubwayBot.cs -> Program.cs ...

if not exist "%BOT_SRC%" (
    echo [bot] ERROR: %BOT_SRC% not found
    set "BOT_OK=0"
    goto summary
)

copy /Y "%BOT_SRC%" "%BOT_PROG%" >nul
if errorlevel 1 (
    echo [bot] ERROR: copy failed
    set "BOT_OK=0"
    goto summary
)

echo [bot] building SubwayBot (.NET 8, x64) ...
pushd "%BOT_DIR%"
dotnet build -c Release -p:PlatformTarget=x64 --nologo -v quiet
if errorlevel 1 (
    echo [bot] BUILD FAILED
    popd
    set "BOT_OK=0"
    goto summary
)
popd

echo [bot] OK — %BOT_EXE%
set "BOT_OK=1"

:: ── summary + optional launch ─────────────────────────────────────────────────

:summary
echo.
echo ─────────────────────────────────────────────
if "%DO_RECON%"=="1" (
    if "%RECON_OK%"=="1" ( echo   recon.dll   OK ) else ( echo   recon.dll   FAILED )
)
if "%DO_BOT%"=="1" (
    if "%BOT_OK%"=="1"   ( echo   SubwayBot   OK ) else ( echo   SubwayBot   FAILED )
)
echo ─────────────────────────────────────────────
echo.

if "%DO_RUN%"=="0" goto end

if not "%BOT_OK%"=="1" (
    echo [run] skipping launch — SubwayBot build failed
    goto end
)

echo [run] launching SubwayBot ...
start "" "%BOT_EXE%"

:end
endlocal