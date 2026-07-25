# One-command rebuild after teardown (~10 min).
param([string]$AlertEmail = $env:NETOPS_ALERT_EMAIL,
      [string]$OperatorEmail = $env:NETOPS_ALERT_EMAIL,
      [string]$OperatorPassword)
$ErrorActionPreference = "Continue"

# call deploy_lab.ps1 rather than re-implementing it: it flips CONFIG#MODE=maintenance first,
# which is what stops the detector raising incidents for CloudFormation's own changes (ADR 0002).
.\scripts\deploy_lab.ps1
.\scripts\deploy_platform.ps1 -AlertEmail $AlertEmail
.venv\Scripts\python scripts\seed_baseline.py
.\scripts\deploy_ui.ps1
if ($OperatorPassword) { .\scripts\create_user.ps1 -Email $OperatorEmail -Password $OperatorPassword }
Write-Host "restored." -ForegroundColor Green
