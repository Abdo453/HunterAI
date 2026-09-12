@echo off
chcp 65001 >nul
title HunterAI Autonomous Security Platform - Unified Controller
color 0A

echo ===============================================================================
echo   ⚡ HunterAI / PentestAI Unified - One-Click Master Launcher
echo ===============================================================================
echo [*] Initializing Autonomous Security OS...
echo [*] Checking Python Environment...

set PYTHONIOENCODING=utf-8
set WEB_PORT=7070
set WEB_HOST=127.0.0.1

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python is not installed or not in PATH!
    pause
    exit /b 1
)

echo [*] Starting HunterAI Web Engine on http://localhost:%WEB_PORT% ...
echo [*] Burp Suite Proxy Target: http://127.0.0.1:8080 (Make sure Burp is open if using proxy)
echo.

start "" cmd /c "timeout /t 3 >nul && start http://localhost:%WEB_PORT%"

python main.py

pause
