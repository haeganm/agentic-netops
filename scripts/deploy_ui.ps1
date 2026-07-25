# Publish the console: generate config.js from stack outputs, sync, invalidate.
$ErrorActionPreference = "Continue"
$out = @{}
$raw = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs" | ConvertFrom-Json
foreach ($o in $raw) { $out[$o.OutputKey] = $o.OutputValue }

@"
const CONFIG = {
  apiUrl: "$($out.ApiUrl)",
  region: "us-east-1",
  clientId: "$($out.UserPoolClientId)",
};
"@ | Out-File -Encoding utf8 ui\config.js

aws s3 cp ui\index.html "s3://$($out.UiBucketName)/index.html" --content-type "text/html" | Out-Null
aws s3 cp ui\config.js "s3://$($out.UiBucketName)/config.js" --content-type "application/javascript" | Out-Null
aws cloudfront create-invalidation --distribution-id $out.UiDistributionId --paths "/*" | Out-Null
Write-Host "console live at $($out.UiUrl)" -ForegroundColor Green
