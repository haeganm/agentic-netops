# Costs

Region: us-east-1. Account budget: $10/month with email alerts at 20% / 100%.
Project cost target: **≤ $15 total, $0.00 idle** — same discipline as v1, harder workload.

## The one metered oracle

| Item | Unit | Bound |
|---|---|---|
| VPC Reachability Analyzer | $0.10/analysis | **Hard cap 30 = $3.00**, enforced in code (ADR 0005): atomic DynamoDB counter consumed before every `StartNetworkInsightsAnalysis`; past the cap incidents close as `VERIFICATION_LIMITED` and a CloudWatch alarm fires — never silently unverified. |

## Everything else

| Service | Why ~$0 |
|---|---|
| Bedrock Nova Micro | ~3.5k in / 700 out tokens per incident ≈ $0.0002; hundreds of incidents ≪ $0.50 |
| Step Functions STANDARD | ~30 transitions/incident, 4,000 free/month |
| Lambda (9 functions, arm64) | free tier covers demo volume many times over |
| DynamoDB | PROVISIONED 3+1 RCU / 3+1 WCU inside the 25/25 always-free tier |
| SQS / EventBridge / SNS / Cognito / CloudFront / S3 | free tier |
| CloudTrail | first copy of management events free (write-only selector); 1-day S3 lifecycle |
| CloudWatch | explicit 7-day log retention on every function; 4 alarms + 2 metric filters (all inside the free tier) |
| Lab VPC | VPC, subnets, route tables, NACLs, SGs, IGW, gateway endpoint, unattached ENIs, NetworkInsights paths: all $0 |

## Deliberately excluded (each $1–$32/month of nothing at this scale)

NAT Gateway, interface VPC endpoints, AWS Config recorder, Network Firewall,
customer-managed KMS, OpenSearch/vector stores, provisioned concurrency, Bedrock
Guardrails. The probe Lambda is designed around the missing NAT: it makes zero AWS API
calls and returns its verdict in the invocation response.

Never script against the Cost Explorer API ($0.01/request — it was 87% of last month's
bill on v1). Cost checks go through the Billing console or the free Budgets API.

## Actuals

| Date | Month-to-date | Note |
|---|---|---|
| 2026-07-24 | ~$2 | build day: RA counter 18/30 ($3.00 cap, $1.80 consumed; failed/over-counted analyses may bill less) + Bedrock cents across ~15 live incidents. Idle bill from here: $0.00. |
| 2026-07-24 (later) | ~$3 | autonomy-tiers + assurance passes: a handful more RA analyses across per-tier smokes, plus the post-tiers regression. Still well inside the $3.00 RA cap and the $10 budget. |
| 2026-07-25 | ~$4 | full eval re-run with tiers live (6 RA analyses, ~$0.60 — docs/evals.md) plus the guard-rail verification passes (read-only, $0). The preserved DynamoDB export froze the RA counter at **25/30** ($2.50 consumed lifetime); the counter reset to 0/30 at the post-teardown rebuild. *(Row reconciled 2026-09-01 — this table is the authoritative spend record per docs/artifacts/README.md and had fallen a day behind the evidence it governs.)* |
