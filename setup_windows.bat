@echo off
chcp 65001 >nul
title HunterAI - Windows Complete Environment Installer
color 0B

echo ===============================================================================
echo   ⚡ HunterAI / PentestAI Unified — Windows All-in-One Installer
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

echo [3/4] Checking Ollama Models...
echo If you want to download any additional recommended models, run:
echo   ollama pull sylink:8b
echo.

echo [4/4] Verifying System Certification (15 Inviolable Gates)...
python certify.py

echo.
echo ===============================================================================
echo   🎉 Installation & Verification Complete!
echo   Run 'run_hunterai.bat' to start the Master Hub!
echo ===============================================================================
pause
