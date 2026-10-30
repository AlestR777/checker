@echo off
cd /d "%~dp0"
python -m threatwatch watch --every-hours 6
pause
