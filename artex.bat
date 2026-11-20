@echo off
REM ==============================================================================
REM  ARTEX-Pro Windows Launcher (Go Core + PostgreSQL + Next.js)
REM ==============================================================================

echo ==================================================================
echo   ⚡ ARTEX-Pro Unified System Launcher (Windows / WSL2)
echo ==================================================================

if "%1"=="scan" (
    if "%2"=="" (
        echo Usage: artex.bat scan [target.com]
        exit /b 1
    )
    echo [+] Executing autonomous Go scan on %2 via WSL...
    wsl -e bash -c "cd /mnt/e/Agant/PentestAI-Unified/backend && bin/artex-server -target %2"
    exit /b 0
)

echo [+] Starting Go Backend & Next.js Frontend...
start "ARTEX-Pro Go Backend" wsl -e bash -c "cd /mnt/e/Agant/PentestAI-Unified/backend && bin/artex-server -server -port 7071"
cd frontend
npm run dev
