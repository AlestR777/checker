@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
title ThreatWatch Global 6.0.2
where py >nul 2>nul
if not errorlevel 1 (
    set "PY=py -3"
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo Python 3.11 or newer is required. Install Python from python.org.
        pause
        exit /b 1
    )
    set "PY=python"
)
%PY% -c "import truststore, certifi" >nul 2>nul
if errorlevel 1 (
    echo Installing required certificates libraries for the first run...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Could not install dependencies. See README_RU.md.
        pause
        exit /b 1
    )
)
%PY% -m threatwatch --version
if errorlevel 1 (
    echo Cannot load ThreatWatch from this folder. Extract the full ZIP first.
    pause
    exit /b 1
)
echo Starting ThreatWatch 6.0.2 on a NEW private port.
echo The server identity and installation files will be checked before opening the browser.
echo Use only the VERIFIED dashboard link printed below, not an old bookmark on port 8765.
echo Closing this window stops the app and its 6-hour schedule.
%PY% -m threatwatch desktop
if errorlevel 1 (
    echo Start failed. Read the error above. Application and database paths are shown in the console.
    pause
)
