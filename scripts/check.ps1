# Local CI: exactly what .github/workflows/ci.yml runs. Use before every commit/deploy.
# Deliberately uses the venv interpreter -- an earlier version called bare `python`, which
# resolved to the system install (no boto3/moto), so the pytest stage never actually ran.
$ErrorActionPreference = "Continue"

$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "no .venv found - create it first:" -ForegroundColor Red
    Write-Host "  python -m venv .venv; .venv\Scripts\python -m pip install -r requirements-dev.txt"
    exit 1
}

$failed = @()

& $py -m ruff check src scripts tests
if ($LASTEXITCODE -ne 0) { $failed += "ruff" }

& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { $failed += "pytest" }

# cfn-lint has no runnable __main__; use the venv console script
& (Join-Path $PSScriptRoot "..\.venv\Scripts\cfn-lint.exe") lab/template.yaml
if ($LASTEXITCODE -ne 0) { $failed += "cfn-lint(lab)" }

sam validate --lint
if ($LASTEXITCODE -ne 0) { $failed += "sam validate" }

if ($failed.Count -gt 0) {
    Write-Host "`nFAILED: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "`nall checks green" -ForegroundColor Green
