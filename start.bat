@echo off
title PentestAI Unified - Master Hub
chcp 65001 > nul
cls
echo ==============================================================================
echo    ⚡ PentestAI Unified — Autonomous Cyber Security OS
echo ==============================================================================
echo    [*] Web Dashboard & Control Hub : http://localhost:7070
echo    [*] BurpAgent Traffic Ingestion : http://127.0.0.1:8085
echo    [*] AutonomousBrain OODA Loop   : ACTIVE
echo    [*] Security Intelligence Layer : ACTIVE
echo    [*] Defense-in-Depth Scope Guard: ENFORCED
echo ==============================================================================
echo.
python main.py %*
pause
