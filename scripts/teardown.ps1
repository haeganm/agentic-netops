# Full reversible teardown to a $0.00 idle bill. Rebuild with restore.ps1.
#
# Order matters and is dictated by three things that otherwise make this fail silently:
#   1. the table has deletion protection ON -- CloudFormation cannot delete it, so the whole
#      platform stack rolls back
#   2. CloudFormation refuses to delete a NON-EMPTY S3 bucket, and the SAM artifact bucket is
#      VERSIONED (a plain `s3 rm --recursive` leaves noncurrent versions + delete markers behind)
#   3. CloudFront must be disabled and fully propagated before it can be deleted -- CFN does that
#      itself, but it takes 15-25 minutes and looks like a hang
#
# This script used to print "teardown complete" unconditionally, even if both stack deletions
# had failed. It now fails loudly instead: the whole point is being able to walk away.
$ErrorActionPreference = "Continue"

$failed = @()
function Fail($msg) { $script:failed += $msg; Write-Host "  FAILED: $msg" -ForegroundColor Red }

$out = @{}
$raw = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs" 2>$null | ConvertFrom-Json
foreach ($o in $raw) { $out[$o.OutputKey] = $o.OutputValue }

# ---- empty the unversioned buckets (CFN cannot delete a bucket with objects in it) -----------
if ($out.UiBucketName) {
    Write-Host "emptying $($out.UiBucketName)..."
    aws s3 rm "s3://$($out.UiBucketName)" --recursive | Out-Null
}
$trail = aws cloudformation describe-stack-resources --stack-name netops-platform --logical-resource-id TrailBucket --query "StackResources[0].PhysicalResourceId" --output text 2>$null
if ($trail -and $trail -ne "None") {
    Write-Host "emptying $trail..."
    aws s3 rm "s3://$trail" --recursive | Out-Null
}

# ---- deletion protection is ON for the system-of-record table ---------------------------------
if ($out.TableName) {
    Write-Host "disabling deletion protection on $($out.TableName)..."
    aws dynamodb update-table --table-name $out.TableName --no-deletion-protection-enabled | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "could not disable deletion protection - the stack delete WILL fail" }
} elseif ($raw) {
    Fail "platform stack exists but TableName output was unreadable - deletion protection may still be on"
}

# ---- stacks, platform first (its IAM boundary and probe config reference lab resource ids) ----
function Remove-Stack($name) {
    $exists = aws cloudformation describe-stacks --stack-name $name --query "Stacks[0].StackName" --output text 2>$null
    if (-not $exists -or $exists -eq "None") { Write-Host "  $name already gone"; return }
    Write-Host "deleting $name (CloudFront propagation makes this slow, not stuck)..."
    aws cloudformation delete-stack --stack-name $name
    aws cloudformation wait stack-delete-complete --stack-name $name
    if ($LASTEXITCODE -ne 0) {
        Fail "$name did not reach DELETE_COMPLETE - check: aws cloudformation describe-stack-events --stack-name $name"
    } else { Write-Host "  $name deleted" -ForegroundColor Green }
}
Remove-Stack "netops-platform"
Remove-Stack "netops-lab"

# ---- SAM's own managed artifact stack ----------------------------------------------------------
# Never referenced by the repo (samconfig.toml just sets resolve_s3 = true, which is what created
# it). Left behind it is ~$0, but "completely shut down" should mean completely. SAM recreates it
# automatically on the next deploy.
$samStack = "aws-sam-cli-managed-default"
$samExists = aws cloudformation describe-stacks --stack-name $samStack --query "Stacks[0].StackName" --output text 2>$null
if ($samExists -and $samExists -ne "None") {
    $samBucket = aws cloudformation describe-stack-resources --stack-name $samStack --logical-resource-id SamCliSourceBucket --query "StackResources[0].PhysicalResourceId" --output text 2>$null
    if ($samBucket -and $samBucket -ne "None") {
        # VERSIONED bucket: every version AND every delete marker must go, or it stays non-empty
        # and the stack delete fails. `aws s3 rm --recursive` only removes current versions.
        Write-Host "emptying versioned bucket $samBucket (all versions + delete markers)..."
        do {
            $page = aws s3api list-object-versions --bucket $samBucket --max-keys 500 --output json | ConvertFrom-Json
            $ids = @()
            foreach ($v in @($page.Versions) + @($page.DeleteMarkers)) {
                if ($v) { $ids += @{ Key = $v.Key; VersionId = $v.VersionId } }
            }
            if ($ids.Count -gt 0) {
                $payload = @{ Objects = $ids; Quiet = $true } | ConvertTo-Json -Depth 5 -Compress
                $tmp = New-TemporaryFile
                [IO.File]::WriteAllText($tmp, $payload)
                aws s3api delete-objects --bucket $samBucket --delete "file://$tmp" | Out-Null
                Remove-Item $tmp -Force
                Write-Host "  removed $($ids.Count) versions/markers"
            }
        } while ($ids.Count -gt 0)
    }
    Remove-Stack $samStack
}

# ---- verify, don't assert --------------------------------------------------------------------
# These names are DETERMINISTIC, so a survivor doesn't just cost money -- it makes the next
# rebuild fail with "already exists".
Write-Host "`nchecking the resources whose names are fixed across rebuilds:"
$acct = aws sts get-caller-identity --query "Account" --output text
foreach ($check in @(
    @{ what = "bucket netops-platform-ui-$acct"; cmd = { aws s3api head-bucket --bucket "netops-platform-ui-$acct" 2>&1 } },
    @{ what = "log group /aws/apigateway/netops-platform-console";
       cmd = { aws logs describe-log-groups --log-group-name-prefix "/aws/apigateway/netops-platform-console" --query "length(logGroups)" --output text } }
)) {
    $r = & $check.cmd 2>&1 | Out-String
    if ($check.what -like "bucket*") {
        if ($r -match "404|Not Found|NoSuchBucket") { Write-Host "  gone: $($check.what)" -ForegroundColor Green }
        else { Fail "$($check.what) still exists - the next rebuild will fail" }
    } else {
        if ($r.Trim() -eq "0") { Write-Host "  gone: $($check.what)" -ForegroundColor Green }
        else { Fail "$($check.what) still exists - the next rebuild will fail" }
    }
}

if ($failed.Count -gt 0) {
    Write-Host "`nTEARDOWN INCOMPLETE - $($failed.Count) problem(s):" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host "Do NOT assume a `$0 bill. Fix the above, re-run this, then run verify_teardown.ps1."
    exit 1
}
Write-Host "`nstacks deleted. Now PROVE it:" -ForegroundColor Green
Write-Host "  .\scripts\verify_teardown.ps1"
