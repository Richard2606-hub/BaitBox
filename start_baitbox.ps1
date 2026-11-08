# ============================================================================
# BaitBox — One-Click Local Launcher (Windows PowerShell)
# ============================================================================
# Starts both:
# 1. BaitBox Trusted Control Plane (FastAPI Orchestrator M2-M8) on http://localhost:8000
# 2. BaitBox Web Console (Next.js M1) on http://localhost:3000
# ============================================================================

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "Starting BaitBox — Disposable Detonation Chamber for Suspicious Links" -ForegroundColor Cyan
Write-Host "  Control Plane API : http://localhost:8000" -ForegroundColor Green
Write-Host "  Web Console UI    : http://localhost:3000" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Cyan

$env:PYTHONPATH = "$Root\backend"

Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$Root\backend'; Set-Location '$Root'; .\backend\.venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Root\frontend'; npm run dev"
