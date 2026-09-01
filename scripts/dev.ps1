# One-command local env: containers + venv + local model.
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")  # anchors cwd first: docker-compose.yml + .venv live at repo root
docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Host "docker compose failed - is Docker running?" -ForegroundColor Red; exit 1 }
if (-not (Test-Path .venv)) {
    # macOS/Linux usually ship python3 with no `python` alias
    $sysPy = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }
    & $sysPy -m venv .venv
}
& $py -m pip install -q -r requirements-dev.txt
docker compose exec ollama ollama pull llama3.2:1b
if ($LASTEXITCODE -ne 0) { Write-Host "ollama model pull failed - dev env NOT ready" -ForegroundColor Red; exit 1 }
Write-Host "dev env ready: DynamoDB Local :8000, Ollama :11434" -ForegroundColor Green
