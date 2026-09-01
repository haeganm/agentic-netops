# One-command local env: containers + venv + local model.
$ErrorActionPreference = "Stop"
docker compose up -d
if (-not (Test-Path .venv)) {
    # macOS/Linux usually ship python3 with no `python` alias
    $sysPy = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }
    & $sysPy -m venv .venv
}
. (Join-Path $PSScriptRoot "common.ps1")
& $py -m pip install -q -r requirements-dev.txt
docker compose exec ollama ollama pull llama3.2:1b
Write-Host "dev env ready: DynamoDB Local :8000, Ollama :11434" -ForegroundColor Green
