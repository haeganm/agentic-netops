# Eval-gated model release (v1 pattern): a candidate model deploys ONLY if it passes
# the full eval suite. Usage: .\scripts\release_model.ps1 -ModelId us.amazon.nova-lite-v1:0
param([Parameter(Mandatory)][string]$ModelId)
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "common.ps1")

# capture the CURRENTLY-deployed model so rollback restores THAT, not the template default
$prev = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Parameters[?ParameterKey=='ModelId'].ParameterValue" --output text
if (-not $prev -or $prev -eq "None") { $prev = "us.amazon.nova-micro-v1:0" }
Write-Host "current model: $prev ; deploying candidate $ModelId to eval against it..."

sam build; if ($LASTEXITCODE -ne 0) { exit 1 }
sam deploy --parameter-overrides "ModelId=$ModelId" | Out-Null  # other params retain previous values
if ($LASTEXITCODE -ne 0) {
    # an unchecked failure here would eval the INCUMBENT model and record a PASS for a
    # candidate that was never live
    Write-Host "candidate deploy failed - nothing evaluated, nothing released" -ForegroundColor Red
    exit 1
}

$env:MODEL_ID = $ModelId
# no assignment on the pipeline: capturing Tee-Object's passthrough silenced the live eval
# output, so the operator watched ~20 minutes of nothing
& $py scripts/evaluate.py 2>&1 | Tee-Object -Variable evalOut
$resultLine = $evalOut | Select-String "^RESULT" | Select-Object -First 1
if (-not $resultLine) {
    # a crashed evaluate.py must read as "nothing was proven", not a null-reference error
    Write-Host "GATE FAIL - evaluate.py emitted no RESULT line (crashed or was interrupted)" -ForegroundColor Red
} elseif ("$resultLine" -match "det=(\d+)/(\d+) diagnosed=(\d+)/(\d+) remediated=(\d+)/(\d+)") {
    $det = [int]$Matches[1]; $total = [int]$Matches[2]
    $diag = [int]$Matches[3]; $rem = [int]$Matches[5]
    # all three gates from docs/evals.md: det 9/9 (harness sanity), diagnosis >= 8/9,
    # remediation 9/9 (never depends on the model, so a miss is a platform bug)
    if ($det -eq $total -and $diag -ge ($total - 1) -and $rem -eq $total) {
        Write-Host "GATE PASS (det $det/$total, diagnosed $diag/$total, remediated $rem/$total) - $ModelId released" -ForegroundColor Green
        exit 0
    }
    Write-Host "GATE FAIL ($resultLine)" -ForegroundColor Red
} else {
    Write-Host "GATE FAIL - RESULT line did not parse: $resultLine" -ForegroundColor Red
}
Write-Host "rolling back to $prev" -ForegroundColor Red
sam deploy --parameter-overrides "ModelId=$prev" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ROLLBACK FAILED - the failing candidate $ModelId is still deployed" -ForegroundColor Red
}
exit 1
