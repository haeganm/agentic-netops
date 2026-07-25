# Deploy the platform stack, feeding it the lab stack's resource IDs.
param([string]$AlertEmail = $env:NETOPS_ALERT_EMAIL)
if (-not $AlertEmail) {
    Write-Host 'set an alert email: -AlertEmail you@example.com  (or $env:NETOPS_ALERT_EMAIL)' -ForegroundColor Red
    exit 1
}
# native tools write progress to stderr; gate on exit codes, not stderr
$ErrorActionPreference = "Continue"

$lab = aws cloudformation describe-stacks --stack-name netops-lab --query "Stacks[0].Outputs" | ConvertFrom-Json
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
