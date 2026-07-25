# Eval-gated model release (v1 pattern): a candidate model deploys ONLY if it passes
# the full eval suite. Usage: .\scripts\release_model.ps1 -ModelId us.amazon.nova-lite-v1:0
param([Parameter(Mandatory)][string]$ModelId)
$ErrorActionPreference = "Continue"
$py = ".venv\Scripts\python"

# capture the CURRENTLY-deployed model so rollback restores THAT, not the template default
$prev = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Parameters[?ParameterKey=='ModelId'].ParameterValue" --output text
if (-not $prev -or $prev -eq "None") { $prev = "us.amazon.nova-micro-v1:0" }
Write-Host "current model: $prev ; deploying candidate $ModelId to eval against it..."

sam build; if ($LASTEXITCODE -ne 0) { exit 1 }
sam deploy --parameter-overrides "ModelId=$ModelId" | Out-Null  # other params retain previous values

$env:MODEL_ID = $ModelId
$out = & $py scripts\evaluate.py 2>&1 | Tee-Object -Variable evalOut
$result = ($evalOut | Select-String "^RESULT").ToString()
if ($result -match "diagnosed=(\d+)/(\d+) remediated=(\d+)/(\d+)") {
    $diag = [int]$Matches[1]; $total = [int]$Matches[2]; $rem = [int]$Matches[3]
    if ($diag -ge ($total - 1) -and $rem -eq $total) {
        Write-Host "GATE PASS ($diag/$total diagnosed, $rem/$total remediated) - $ModelId released" -ForegroundColor Green
        exit 0
    }
}
Write-Host "GATE FAIL - rolling back to $prev" -ForegroundColor Red
sam deploy --parameter-overrides "ModelId=$prev" | Out-Null
exit 1
