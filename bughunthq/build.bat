@echo off
REM Build BugHuntHQ.exe on Windows.
REM Run this from the "bughunthq" folder (Command Prompt or PowerShell).

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH. Install Python 3.10+ from https://www.python.org/downloads/windows/
    echo and check "Add python.exe to PATH" during install, then re-run this script.
    exit /b 1
)

echo [1/3] Creating virtual environment (.venv)...
python -m venv .venv
call .venv\Scripts\activate.bat

echo [2/3] Installing dependencies...
pip install --upgrade pip >nul
pip install -r requirements.txt

echo [3/3] Building BugHuntHQ.exe with PyInstaller...
pyinstaller --onefile --windowed --name BugHuntHQ bughunthq.py

echo.
echo Done. Your exe is at dist\BugHuntHQ.exe
pause
