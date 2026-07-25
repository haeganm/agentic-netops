# One-command local env: containers + venv + local model.
$ErrorActionPreference = "Stop"
docker compose up -d
if (-not (Test-Path .venv)) { python -m venv .venv }
.venv\Scripts\python -m pip install -q -r requirements-dev.txt
docker compose exec ollama ollama pull llama3.2:1b
Write-Host "dev env ready: DynamoDB Local :8000, Ollama :11434" -ForegroundColor Green
