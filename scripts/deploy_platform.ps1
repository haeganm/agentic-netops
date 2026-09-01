# Deploy the platform stack, feeding it the lab stack's resource IDs.
param([string]$AlertEmail = $env:NETOPS_ALERT_EMAIL)
if (-not $AlertEmail) {
    Write-Host 'set an alert email: -AlertEmail you@example.com  (or $env:NETOPS_ALERT_EMAIL)' -ForegroundColor Red
    exit 1
}
# native tools write progress to stderr; gate on exit codes, not stderr
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "common.ps1")  # anchors cwd to the repo root for sam build/deploy

if (-not (Get-Command sam -ErrorAction SilentlyContinue)) {
    # CommandNotFound leaves $LASTEXITCODE untouched -- without this guard the script used
    # to exit 0 having deployed nothing
    Write-Host "sam CLI not found - install AWS SAM CLI first" -ForegroundColor Red
    exit 1
}
$lab = aws cloudformation describe-stacks --stack-name netops-lab --query "Stacks[0].Outputs" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $lab) {
    Write-Host "cannot read netops-lab outputs - deploy the lab stack first (deploy_lab.ps1)" -ForegroundColor Red
    exit 1
}
$out = @{}
foreach ($o in $lab) { $out[$o.OutputKey] = $o.OutputValue }

sam build
if ($LASTEXITCODE -ne 0) { exit 1 }
sam deploy --parameter-overrides `
    "AlertEmail=$AlertEmail" `
    "LabPrivateSubnetId=$($out.PrivateSubnetId)" `
    "ProbeSgId=$($out.ProbeSgId)" `
    "LabVpcId=$($out.VpcId)"
if ($LASTEXITCODE -ne 0) { exit 1 }
