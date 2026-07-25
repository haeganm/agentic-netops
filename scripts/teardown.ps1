# Full reversible teardown: empties buckets, deletes both stacks. Restore with restore.ps1.
$ErrorActionPreference = "Continue"

$out = @{}
$raw = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs" 2>$null | ConvertFrom-Json
foreach ($o in $raw) { $out[$o.OutputKey] = $o.OutputValue }

if ($out.UiBucketName) { aws s3 rm "s3://$($out.UiBucketName)" --recursive | Out-Null }
$trail = aws cloudformation describe-stack-resources --stack-name netops-platform --logical-resource-id TrailBucket --query "StackResources[0].PhysicalResourceId" --output text 2>$null
if ($trail -and $trail -ne "None") { aws s3 rm "s3://$trail" --recursive | Out-Null }

# deletion protection is ON for the system-of-record table -- disable it so the stack can delete
if ($out.TableName) {
    aws dynamodb update-table --table-name $out.TableName --no-deletion-protection-enabled | Out-Null
}

Write-Host "deleting netops-platform..."
aws cloudformation delete-stack --stack-name netops-platform
aws cloudformation wait stack-delete-complete --stack-name netops-platform
Write-Host "deleting netops-lab..."
aws cloudformation delete-stack --stack-name netops-lab
aws cloudformation wait stack-delete-complete --stack-name netops-lab

Write-Host "`nsweep - anything left that could bill:"
aws ec2 describe-vpcs --filters "Name=tag:Project,Values=agentic-netops" --query "Vpcs[].VpcId"
aws ec2 describe-network-interfaces --filters "Name=tag:Project,Values=agentic-netops" --query "NetworkInterfaces[].NetworkInterfaceId"
aws cloudtrail describe-trails --query "trailList[].Name"
Write-Host "teardown complete - idle bill `$0.00" -ForegroundColor Green
