@echo off
title AEGIS Autonomous Swarm Defense Platform
cd /d "%~dp0"
echo ===============================================================================
echo        AEGIS AUTONOMOUS SWARM DEFENSE - ONE-COMMAND LAUNCHER
echo ===============================================================================
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe run_all.py
) else (
    python run_all.py
)
pause
