# The showcase: break the network on camera, approve from the console, watch it heal.
# Usage: .\scripts\demo.ps1 [-Fault sg-ingress-removed]
param([string]$Fault = "sg-ingress-removed")
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "common.ps1")

# guarded like create_user.ps1: without this, a missing platform stack seeded the fault
# anyway and then polled `--table-name ""` forever
$t = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs[?OutputKey=='TableName'].OutputValue" --output text
if ($LASTEXITCODE -ne 0 -or -not $t -or $t -eq "None") {
    Write-Host "cannot resolve TableName from netops-platform - is the platform stack deployed (and the region us-east-1)?" -ForegroundColor Red
    exit 1
}
$ui = aws cloudformation describe-stacks --stack-name netops-platform --query "Stacks[0].Outputs[?OutputKey=='UiUrl'].OutputValue" --output text

# must match shared.status.TERMINAL -- omitting one makes a correct outcome poll forever
$terminal = @("RESOLVED","VERIFICATION_LIMITED","FAILED","GATE_BLOCKED","EXPIRED","REJECTED",
              "CANCELLED","FALSE_POSITIVE")

# Captured BEFORE seeding, compared against gsi1sk (the incident's created_at): without the
# time filter, the poll below picks up the PREVIOUS demo's already-terminal incident and
# reports it as this run's result in ~0s. Same technique evaluate.py uses (incidents_since).
$seedIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
& $py scripts/chaos.py $Fault
if ($LASTEXITCODE -ne 0) { exit 1 }
$seed = Get-Date
Write-Host "`nfault seeded. watch the console: $ui" -ForegroundColor Yellow
Write-Host "the autonomy tier decides what happens next (ADR 0011):"
Write-Host "  LOW    -> AUTO_EXEC_PENDING: a ~60s veto window. Do nothing and it self-heals; CANCEL to veto."
Write-Host "  MEDIUM -> AWAITING_APPROVAL: click APPROVE."
Write-Host "  HIGH   -> AWAITING_APPROVAL, then AWAITING_SECOND_APPROVAL: a SECOND, distinct operator must approve.`n"

# JSON for the aws CLI goes through a file: inline `\"` escaping parses differently between
# Windows PowerShell 5.1 and pwsh 7 on macOS/Linux (where the backslashes arrive literally).
$vals = New-TemporaryFile
@{ ":p" = @{ S = "INC" }; ":t" = @{ S = $seedIso } } | ConvertTo-Json -Compress | Set-Content $vals

Write-Host "(silence for the first 1-3 minutes is normal: CloudTrail delivery latency)" -ForegroundColor DarkGray
$last = ""
try {
    while ($true) {
        $items = aws dynamodb query --table-name $t --index-name GSI1 --key-condition-expression "gsi1pk = :p AND gsi1sk >= :t" --expression-attribute-values "file://$vals" --query "Items" | ConvertFrom-Json
        $newest = $items | Sort-Object {$_.gsi1sk.S} -Descending | Select-Object -First 1
        if ($newest) {
            $s = "$($newest.pk.S.Split('#')[1]) $($newest.status.S) [tier=$($newest.tier.S)]"
            if ($s -ne $last) { Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $s"; $last = $s }
            if ($newest.status.S -in $terminal) {
                $mttr = [int]((Get-Date) - $seed).TotalSeconds
                Write-Host "`nterminal: $($newest.status.S) - wall clock seed->terminal ${mttr}s" -ForegroundColor Green
                break
            }
        }
        Start-Sleep -Seconds 10
    }
} finally {
    Remove-Item $vals -Force -ErrorAction SilentlyContinue
}
