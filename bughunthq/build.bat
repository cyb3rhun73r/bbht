@echo off
REM Build BugHuntHQ.exe on Windows.
REM Run this from the "bughunthq" folder (Command Prompt or PowerShell).

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH. Install Python 3.10+ from https://www.python.org/downloads/windows/
    echo and check "Add python.exe to PATH" during install, then re-run this script.
    exit /b 1
)

echo [1/4] Creating virtual environment (.venv)...
python -m venv .venv
call .venv\Scripts\activate.bat

echo [2/4] Installing dependencies...
pip install --upgrade pip >nul
pip install -r requirements.txt

echo [3/4] Fetching/vendoring attack tools into tools\ ...
python tools\fetch_tools.py

echo [4/4] Building BugHuntHQ.exe with PyInstaller...
pyinstaller --onefile --windowed --name BugHuntHQ bughunthq.py

echo [*] Bundling tools\ next to the built exe...
if not exist dist\tools mkdir dist\tools
xcopy /E /I /Y tools dist\tools >nul

echo.
echo Done. Your app is dist\BugHuntHQ.exe with its dist\tools\ folder beside it.
echo Copy the whole dist\ folder together - the exe looks for tools\ next to itself.
pause
