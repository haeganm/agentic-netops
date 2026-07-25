# ADR 0010: IAM least-privilege hardening — key-scoped writes, tag-scoped ceiling

**Status**: accepted (2026-07-24)

## Context
A three-front adversarial audit found the governance claims were partly aspirational:
1. every Lambda role could `PutItem` any item, so any compromised function could rewrite
   `CONFIG#BASELINE` — the definition of "correct" that the planner and gate both trust —
   or flip `CONFIG#MODE` to silently disable detection;
2. the permissions boundary (the "hard ceiling") was `Resource: "*"` with only a region
   condition, so it actually permitted mutating any SG/route/NACL/VPC/ENI in the region,
   including production;
3. the detector's loop-prevention skipped any actor whose ARN merely *contained*
   `netops-remediation-` — an attacker naming their own session that string went undetected.

## Decision
- **Config is a trust boundary.** `CONFIG#*` items are writable only by the deploy/seed
  admin identity. Every runtime function's `PutItem`/`UpdateItem` carries
  `Condition: dynamodb:LeadingKeys ∈ ["INCIDENT#*"]`. The one runtime-mutable counter (RA
  budget) was moved to its own `LIMITS#RA` partition so the oracles function alone gets a
  narrow grant to it. The state machine's broad `DynamoDBCrudPolicy` was replaced with a
  key-scoped inline `UpdateItem`.
- **The boundary is scoped to the lab, not the region.** Mutating actions require
  `aws:ResourceTag/Project = agentic-netops` (all lab resources carry it). `ModifyVpcAttribute`,
  which does not honor `aws:ResourceTag`, is scoped to the specific lab VPC ARN instead.
  `Describe*` stays broad (Reachability Analyzer needs it). Same conditions on the
  RemediationRole inline policy.
- **Detection matches identity, not substrings.** The detector skips an event only when
  `userIdentity.arn` starts with the exact assumed-role prefix of the RemediationRole
  (`arn:aws:sts::{acct}:assumed-role/{RoleName}/`), derived from `REMEDIATION_ROLE_ARN`.
- A parity test (`tests/test_iam_parity.py`) asserts the mutating-action set agrees across
  the gate allowlist, the STS scoper, and the template IAM, so future edits can't desync them.

## Consequences
- Blast radius of a single compromised runtime function drops from "rewrite ground truth /
  mutate any prod network resource" to "write INCIDENT ledger rows and mutate lab-tagged
  resources only."
- The boundary tag-condition must be live-verified per action (support varies); the
  ModifyVpcAttribute ARN-scoping is the documented fallback for the one action that lacks it.
- Effective remediation permission is now role ∩ (tag-scoped boundary) ∩ (per-incident
  session policy) — three independent rings, each genuinely constraining.
