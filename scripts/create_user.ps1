# Create a console operator (self-signup is disabled by design).
# NOTE: the password transits the aws.exe command line (visible to local process listing) and
# your shell history -- acceptable for lab operators, don't reuse a real password here.
param([Parameter(Mandatory)][string]$Email, [Parameter(Mandatory)][string]$Password)
$ErrorActionPreference = "Continue"
$pool = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text
if ($LASTEXITCODE -ne 0 -or -not $pool -or $pool -eq "None") {
    Write-Host "cannot resolve UserPoolId from netops-platform - is the platform stack deployed?" -ForegroundColor Red
    exit 1
}
aws cognito-idp admin-create-user --user-pool-id $pool --username $Email --message-action SUPPRESS | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "admin-create-user failed for $Email" -ForegroundColor Red; exit 1 }
aws cognito-idp admin-set-user-password --user-pool-id $pool --username $Email --password $Password --permanent
if ($LASTEXITCODE -ne 0) { Write-Host "set-user-password failed for $Email (12+ chars required)" -ForegroundColor Red; exit 1 }
Write-Host "operator $Email ready"
