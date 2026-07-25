# Create a console operator (self-signup is disabled by design).
param([Parameter(Mandatory)][string]$Email, [Parameter(Mandatory)][string]$Password)
$ErrorActionPreference = "Continue"
$pool = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text
aws cognito-idp admin-create-user --user-pool-id $pool --username $Email --message-action SUPPRESS | Out-Null
aws cognito-idp admin-set-user-password --user-pool-id $pool --username $Email --password $Password --permanent
Write-Host "operator $Email ready"
