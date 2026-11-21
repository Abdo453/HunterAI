@echo off
cls
echo ======================================================================
echo    Starting PentestAI Unified on Kali Linux (WSL2)
echo ======================================================================
wsl -d kali-linux -- python3 /mnt/e/Agant/PentestAI-Unified/scripts/kali_monitor.py %*
