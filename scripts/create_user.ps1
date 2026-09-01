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
$createOut = aws cognito-idp admin-create-user --user-pool-id $pool --username $Email --message-action SUPPRESS 2>&1
if ($LASTEXITCODE -ne 0) {
    if ("$createOut" -match "UsernameExistsException") {
        # a prior run that failed at set-password leaves the user half-created
        # (FORCE_CHANGE_PASSWORD); proceed so the rerun can finish instead of dead-ending
        Write-Host "user $Email already exists - setting password on the existing account"
    } else {
        Write-Host "admin-create-user failed for ${Email}: $createOut" -ForegroundColor Red; exit 1
    }
}
aws cognito-idp admin-set-user-password --user-pool-id $pool --username $Email --password $Password --permanent
if ($LASTEXITCODE -ne 0) { Write-Host "set-user-password failed for $Email (policy: 12+ chars with upper, lower and a digit)" -ForegroundColor Red; exit 1 }
Write-Host "operator $Email ready"
