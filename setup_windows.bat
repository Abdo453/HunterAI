@echo off
chcp 65001 >nul
title HunterAI - Windows Complete Environment Installer
color 0B

cd /d "%~dp0"

echo ===============================================================================
echo   HunterAI — Windows All-in-One Environment Installer
echo ===============================================================================
echo.

echo [1/4] Installing / Updating Python Dependencies from requirements.txt...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Warning: Some python packages failed to install.
) else (
    echo [+] Python dependencies installed successfully.
)
echo.

echo [2/4] Installing Headless Chromium for Autonomous Browser Agent...
python -m playwright install chromium
echo.

echo [3/4] Checking Tool Manifests & Skill Mirrors...
python scripts\sync_tool_manifests.py --check
python tools\install_opencode_skills.py --check
echo.

echo [4/4] Checking Ollama Localhost Endpoint (127.0.0.1:11434)...
echo To download a recommended local model, run:
echo   ollama pull qwen2.5:14b
echo.

echo ===============================================================================
echo   Installation & Verification Complete!
echo   Launch Unified Platform: python pentest.py artex
echo ===============================================================================
pause
