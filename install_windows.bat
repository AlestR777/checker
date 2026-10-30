@echo off
setlocal
cd /d "%~dp0"
echo [ThreatWatch] Installing Python dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Failed to install dependencies. Check Python 3.11+ and network access.
  pause
  exit /b 1
)
echo [ThreatWatch] Initializing / upgrading local database...
python -m threatwatch init
if errorlevel 1 (
  pause
  exit /b 1
)
python -m threatwatch doctor
pause
