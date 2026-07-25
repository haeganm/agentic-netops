# ADR 0003: Baseline snapshot differ is the primary intent oracle; CFN drift is advisory

**Status**: accepted (2026-07-24)

## Context
CloudFormation drift detection covers AWS::EC2::SecurityGroup and NetworkAcl, but coverage
for routes, route-table associations, and VPC attributes is partial/unconfirmed. The intent
oracle must adjudicate every fault class or the loop has blind spots.

## Decision
At lab deploy — and *only* at lab deploy — the platform captures a canonical snapshot
of the lab network — security groups, route tables and routes, NACL entries, subnet
associations, VPC DNS attributes — normalized (sorted keys/rules) and stored at
CONFIG#BASELINE. PROVE and VERIFY diff live-vs-baseline in plain Python: full coverage,
deterministic, unit-testable against fixtures. CloudFormation DetectStackDrift runs as a
corroborating secondary signal (ledgered as oracle:intent-cfn) and never blocks the loop.

## Consequences
- Remediation has a precise, machine-readable target: the baseline values themselves.
- The differ is the single most load-bearing module (src/shared/baseline.py) and carries
  the densest test suite.
- The baseline is written by `scripts/seed_baseline.py` alone, so intentional lab changes must
  go through `deploy_lab.ps1` (which re-baselines) — exactly the "changes go through IaC" rule.
- **Deliberately NOT re-baselined after VERIFY.** An earlier draft of this ADR said it was; it
  never was, and it shouldn't be: after a successful verify the diff is empty (so a refresh is a
  no-op), and after a failed one a refresh would enshrine the drift as the new intent. The
  baseline changes only when a human deploys new intent.
