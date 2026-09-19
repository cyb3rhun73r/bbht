@echo off
setlocal enabledelayedexpansion
REM Build BugHuntHQ.exe on Windows 11, from a completely clean machine if
REM needed - this script tries to get every prerequisite in place itself.
REM Run this from the "bughunthq" folder (Command Prompt or PowerShell).

where python >nul 2>nul
if errorlevel 1 (
    echo [1/6] Python not found - attempting to install it automatically via winget...
    where winget >nul 2>nul
    if errorlevel 1 (
        echo.
        echo winget isn't available either. Install Python 3.10+ yourself from
        echo https://www.python.org/downloads/windows/ - check "Add python.exe to PATH"
        echo during install - then re-run this script.
        exit /b 1
    )
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo.
        echo winget could not install Python automatically. Install it yourself from
        echo https://www.python.org/downloads/windows/ - check "Add python.exe to PATH"
        echo during install - then re-run this script.
        exit /b 1
    )
    echo.
    echo Python was installed. Windows needs a NEW terminal window to pick up the
    echo updated PATH - close this window, reopen Command Prompt, and run build.bat
    echo again to continue.
    exit /b 0
) else (
    echo [1/6] Python found.
)

echo [2/6] Creating virtual environment (.venv)...
python -m venv .venv
call .venv\Scripts\activate.bat

echo [3/6] Installing dependencies...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt

echo [4/6] Fetching/vendoring attack tools into tools\ (and their own
echo        dependencies, whatever each tool currently declares)...
python tools\fetch_tools.py

echo [5/6] Fetching the MITRE ATT^&CK dataset (~50MB download, one-time)...
python tools\fetch_attack_data.py

echo [6/6] Building BugHuntHQ.exe with PyInstaller...
set COLLECT_ARGS=
if exist tools\extra-packages.txt (
    echo        Freezing vendored tools' own dependencies into the exe:
    for /f "usebackq delims=" %%P in ("tools\extra-packages.txt") do (
        echo          - %%P
        set COLLECT_ARGS=!COLLECT_ARGS! --collect-all %%P
    )
)
pyinstaller --onefile --windowed --name BugHuntHQ !COLLECT_ARGS! bughunthq.py

echo [*] Bundling tools\ next to the built exe...
if not exist dist\tools mkdir dist\tools
xcopy /E /I /Y tools dist\tools >nul

echo.
echo Done. Your app is dist\BugHuntHQ.exe with its dist\tools\ folder beside it.
echo Copy the whole dist\ folder together - the exe looks for tools\ next to itself.
pause
