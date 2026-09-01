# Publish the console: generate config.js from stack outputs, sync, invalidate.
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "common.ps1")  # anchors cwd to the repo root (ui/ paths below)
$out = @{}
$raw = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $raw) {
    Write-Host "cannot read netops-platform outputs - refusing to publish a config.js with empty apiUrl/clientId" -ForegroundColor Red
    exit 1
}
foreach ($o in $raw) { $out[$o.OutputKey] = $o.OutputValue }
foreach ($k in "ApiUrl", "UserPoolClientId", "UiBucketName", "UiDistributionId") {
    if (-not $out[$k]) { Write-Host "stack output $k missing - aborting UI publish" -ForegroundColor Red; exit 1 }
}

@"
const CONFIG = {
  apiUrl: "$($out.ApiUrl)",
  region: "us-east-1",
  clientId: "$($out.UserPoolClientId)",
};
"@ | Out-File -Encoding utf8 ui/config.js

# forward slashes: these paths are ARGUMENTS to aws.exe, and on macOS/Linux pwsh passes a
# backslash through literally (only PowerShell's own cmdlets normalize separators).
# Every step gated: this script once said "console live" after failed uploads.
aws s3 cp ui/index.html "s3://$($out.UiBucketName)/index.html" --content-type "text/html" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "index.html upload FAILED - console NOT published" -ForegroundColor Red; exit 1 }
aws s3 cp ui/config.js "s3://$($out.UiBucketName)/config.js" --content-type "application/javascript" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "config.js upload FAILED - console NOT published" -ForegroundColor Red; exit 1 }
aws cloudfront create-invalidation --distribution-id $out.UiDistributionId --paths "/*" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "cache invalidation FAILED - console may serve stale files" -ForegroundColor Red; exit 1 }
Write-Host "console live at $($out.UiUrl)" -ForegroundColor Green
