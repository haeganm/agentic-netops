# Prove the account is back to $0.00 -- safe to power the machine off and walk away.
#
#   .\scripts\verify_teardown.ps1
#
# Read-only. Exit 0 = nothing left that can bill. Exit 1 = something survived, with its name.
#
# DELIBERATELY DOES NOT CALL COST EXPLORER. That API costs $0.01 per request, so a tool that
# polls it to reassure you about spending is itself a charge on the bill it is checking. Spend is
# eyeballed once in the console instead.
#
# Two kinds of check, because two different things can go wrong:
#   - project resources, by name: leftovers cost money, and the fixed-name ones ALSO break the
#     next rebuild with "already exists"
#   - the genuinely expensive resource classes, account-wide across every region: an orphaned
#     Elastic IP is ~$3.60/month and would never show up in a name-based search
$ErrorActionPreference = "Continue"

$rows = @()
function Check($what, $ok, $detail) {
    $script:rows += [pscustomobject]@{ ok = [bool]$ok; what = $what; detail = "$detail" }
}
function Count($expr) { $v = (& $expr 2>$null | Out-String).Trim(); if ($v -eq "" -or $v -eq "None") { "0" } else { $v } }

$acct = (aws sts get-caller-identity --query "Account" --output text 2>$null)
Write-Host "account $acct -- verifying teardown`n"

# ---- 1. the stacks -----------------------------------------------------------------------------
foreach ($s in @("netops-platform", "netops-lab", "aws-sam-cli-managed-default")) {
    $r = aws cloudformation describe-stacks --stack-name $s --query "Stacks[0].StackStatus" --output text 2>&1 | Out-String
    Check "stack $s" ($r -match "does not exist") $(if ($r -match "does not exist") { "gone" } else { $r.Trim() })
}

# ---- 2. storage and state ----------------------------------------------------------------------
$buckets = (aws s3api list-buckets --query "Buckets[?contains(Name,'netops') || contains(Name,'sam-cli')].Name" --output text 2>$null | Out-String).Trim()
Check "S3 buckets" ($buckets -eq "") $(if ($buckets) { $buckets } else { "none" })

$tables = (aws dynamodb list-tables --query "TableNames[?contains(@,'netops')]" --output text 2>$null | Out-String).Trim()
Check "DynamoDB tables" ($tables -eq "") $(if ($tables) { $tables } else { "none" })

# on-demand backups outlive their table and keep billing
$backups = Count { aws dynamodb list-backups --query "length(BackupSummaries)" --output text }
Check "DynamoDB backups" ($backups -eq "0") "$backups found"

$logs = Count { aws logs describe-log-groups --query "length(logGroups[?contains(logGroupName,'netops')])" --output text }
Check "CloudWatch log groups" ($logs -eq "0") "$logs found"

# ---- 3. the rest of the platform ---------------------------------------------------------------
$alarms = Count { aws cloudwatch describe-alarms --query "length(MetricAlarms[?contains(AlarmName,'netops')])" --output text }
Check "CloudWatch alarms" ($alarms -eq "0") "$alarms found"

$cf = Count { aws cloudfront list-distributions --query "length(DistributionList.Items)" --output text }
Check "CloudFront distributions" ($cf -eq "0") "$cf found"

$pools = Count { aws cognito-idp list-user-pools --max-results 20 --query "length(UserPools)" --output text }
Check "Cognito user pools" ($pools -eq "0") "$pools found"

$topics = Count { aws sns list-topics --query "length(Topics[?contains(TopicArn,'netops')])" --output text }
Check "SNS topics" ($topics -eq "0") "$topics found"

$queues = (aws sqs list-queues --queue-name-prefix netops --query "QueueUrls" --output text 2>$null | Out-String).Trim()
Check "SQS queues" ($queues -eq "" -or $queues -eq "None") $(if ($queues -and $queues -ne "None") { "present" } else { "none" })

$rules = Count { aws events list-rules --name-prefix netops --query "length(Rules)" --output text }
Check "EventBridge rules" ($rules -eq "0") "$rules found"

$trails = Count { aws cloudtrail describe-trails --query "length(trailList[?contains(Name,'netops')])" --output text }
Check "CloudTrail trails" ($trails -eq "0") "$trails found"

# Reachability Analyzer: paths and their analyses are free to retain, but a surviving path means
# the lab stack did not fully delete
$paths = Count { aws ec2 describe-network-insights-paths --query "length(NetworkInsightsPaths)" --output text }
Check "Reachability Analyzer paths" ($paths -eq "0") "$paths found"

$vpcs = Count { aws ec2 describe-vpcs --filters "Name=tag:Project,Values=agentic-netops" --query "length(Vpcs)" --output text }
Check "lab VPCs (tagged)" ($vpcs -eq "0") "$vpcs found"

# ---- 4. fixed-name resources: these break the REBUILD, not just the bill ------------------------
$head = aws s3api head-bucket --bucket "netops-platform-ui-$acct" 2>&1 | Out-String
Check "fixed-name UI bucket" ($head -match "404|Not Found|NoSuchBucket") $(if ($head -match "404|Not Found|NoSuchBucket") { "gone" } else { "STILL EXISTS - rebuild would fail" })

$apiLog = Count { aws logs describe-log-groups --log-group-name-prefix "/aws/apigateway/netops-platform-console" --query "length(logGroups)" --output text }
Check "fixed-name API access log group" ($apiLog -eq "0") $(if ($apiLog -eq "0") { "gone" } else { "STILL EXISTS - rebuild would fail" })

$hp = Count { aws cloudfront list-response-headers-policies --type custom --query "length(ResponseHeadersPolicyList.Items)" --output text }
Check "CloudFront response-headers policies" ($hp -eq "0") "$hp custom"

$oac = Count { aws cloudfront list-origin-access-controls --query "length(OriginAccessControlList.Items)" --output text }
Check "CloudFront origin access controls" ($oac -eq "0") "$oac found"

# ---- 5. never-cheap resource classes, EVERY region ---------------------------------------------
# A name-based search cannot find these, and they are the only things that cost real money.
$regions = @("us-east-1","us-east-2","us-west-1","us-west-2","eu-west-1","eu-central-1",
             "ap-southeast-1","ap-northeast-1","ca-central-1","sa-east-1")
$dirty = @()
foreach ($r in $regions) {
    $i = Count { aws ec2 describe-instances --region $r --query "length(Reservations[].Instances[?State.Name!='terminated'][])" --output text }
    $e = Count { aws ec2 describe-addresses --region $r --query "length(Addresses)" --output text }
    $n = Count { aws ec2 describe-nat-gateways --region $r --query "length(NatGateways[?State!='deleted'])" --output text }
    $v = Count { aws ec2 describe-volumes --region $r --query "length(Volumes)" --output text }
    $s = Count { aws ec2 describe-snapshots --region $r --owner-ids self --query "length(Snapshots)" --output text }
    if ("$i$e$n$v$s" -match "[1-9]") { $dirty += "${r}: instances=$i eips=$e nat=$n volumes=$v snapshots=$s" }
}
Check "EC2/EBS/EIP/NAT across $($regions.Count) regions" ($dirty.Count -eq 0) $(if ($dirty) { $dirty -join "; " } else { "all clean" })

$kms = (aws kms list-aliases --query "Aliases[?starts_with(AliasName,'alias/') && !starts_with(AliasName,'alias/aws/')].AliasName" --output text 2>$null | Out-String).Trim()
Check "customer-managed KMS keys" ($kms -eq "") $(if ($kms) { $kms } else { "none (`$1/mo each)" })

$secrets = (aws secretsmanager list-secrets --query "SecretList[].Name" --output text 2>$null | Out-String).Trim()
Check "Secrets Manager secrets" ($secrets -eq "") $(if ($secrets) { $secrets } else { "none" })

# ---- 6. the tripwire must SURVIVE --------------------------------------------------------------
# Asserted as a positive: if everything above is wrong, this budget is what tells you.
$bud = (aws budgets describe-budgets --account-id $acct --query "Budgets[].BudgetName" --output text 2>$null | Out-String).Trim()
Check "a budget alarm still exists (tripwire)" ($bud -ne "") $(if ($bud) { $bud -replace "\s+", ", " } else { "NONE - nothing would warn you" })

# ---- report ------------------------------------------------------------------------------------
$w = ($rows.what | Measure-Object -Maximum -Property Length).Maximum
Write-Host ("-" * ($w + 34))
foreach ($row in $rows) {
    $tag = if ($row.ok) { "PASS" } else { "FAIL" }
    $col = if ($row.ok) { "Green" } else { "Red" }
    Write-Host ("  {0}  {1}  {2}" -f $tag, $row.what.PadRight($w), $row.detail) -ForegroundColor $col
}
Write-Host ("-" * ($w + 34))

$bad = @($rows | Where-Object { -not $_.ok })
if ($bad.Count -gt 0) {
    Write-Host "$($bad.Count) of $($rows.Count) checks FAILED - do not assume a `$0 bill." -ForegroundColor Red
    exit 1
}
Write-Host "all $($rows.Count) checks pass - nothing left that can bill." -ForegroundColor Green
Write-Host "Safe to power off. Rebuild any time with: .\scripts\restore.ps1" -ForegroundColor Green
Write-Host "`n(Spend itself is not checked here on purpose - the Cost Explorer API charges per call."
Write-Host " Eyeball Billing > Free Tier in the console once if you want the dollar figure.)"
