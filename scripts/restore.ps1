# One-command rebuild after teardown (~10 min).
param([string]$AlertEmail = $env:NETOPS_ALERT_EMAIL,
      [string]$OperatorEmail = $env:NETOPS_ALERT_EMAIL,
      [string]$OperatorPassword)
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "common.ps1")

# call deploy_lab.ps1 rather than re-implementing it: it flips CONFIG#MODE=maintenance first,
# which is what stops the detector raising incidents for CloudFormation's own changes (ADR 0002).
# every step gates the next: a rebuild that half-succeeds must say so, not print "restored."
.\scripts\deploy_lab.ps1
.\scripts\deploy_platform.ps1 -AlertEmail $AlertEmail
if ($LASTEXITCODE -ne 0) { Write-Host "restore FAILED at platform deploy" -ForegroundColor Red; exit 1 }
& $py scripts/seed_baseline.py
if ($LASTEXITCODE -ne 0) { Write-Host "restore FAILED at baseline seed" -ForegroundColor Red; exit 1 }
.\scripts\deploy_ui.ps1
if ($LASTEXITCODE -ne 0) { Write-Host "restore FAILED at UI deploy" -ForegroundColor Red; exit 1 }
if ($OperatorPassword) {
    .\scripts\create_user.ps1 -Email $OperatorEmail -Password $OperatorPassword
    if ($LASTEXITCODE -ne 0) { Write-Host "restore FAILED at operator creation" -ForegroundColor Red; exit 1 }
}
Write-Host "restored." -ForegroundColor Green
