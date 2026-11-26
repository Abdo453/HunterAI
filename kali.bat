@echo off
cls
echo ======================================================================
echo    Starting HunterAI Monitor on Kali Linux (WSL2)
echo ======================================================================
set "WIN_REPO=%~dp0"
for /f "usebackq delims=" %%i in (`wsl -d kali-linux -- wslpath -u "%WIN_REPO%"`) do set "WSL_REPO=%%i"
wsl -d kali-linux -- python3 "%WSL_REPO%/scripts/kali_monitor.py" %*
