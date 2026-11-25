# Aegex preprocessing - full pipeline.
# Usage (from any folder):  powershell -ExecutionPolicy Bypass -File run_all.ps1 [-Python path\to\python.exe]
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($step in "step1_flows.py", "step2_features.py", "step3_sequences_graphs.py", "step4_verify.py", "step5_baseline.py") {
    Write-Host "=== $step ==="
    & $Python -I (Join-Path $here $step)
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}
Write-Host "Done. See preprocessed\_verification.txt and preprocessed\baseline\summary.txt"
