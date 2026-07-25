# Deploy (or update) the lab network, then re-capture the declared baseline.
# Maintenance mode makes the detector ignore CloudFormation's own changes (ADR 0002).
# native tools write progress to stderr; gate on exit codes, not stderr
$ErrorActionPreference = "Continue"
$py = ".venv\Scripts\python"

# best-effort: platform stack (and table) may not exist on the very first deploy
& $py scripts\seed_baseline.py --mode maintenance 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "platform stack not up yet - skipping maintenance flag" }

aws cloudformation deploy --template-file lab/template.yaml --stack-name netops-lab --no-fail-on-empty-changeset
if ($LASTEXITCODE -ne 0) { exit 1 }

& $py scripts\seed_baseline.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "baseline NOT captured (deploy platform stack first, then rerun: python scripts\seed_baseline.py)"
}
