# ADR 0004: The remediation policy gate is a versioned Python module, not cfn-guard

**Status**: accepted (2026-07-24)

## Context
Every remediation plan must pass a deterministic safety gate before a human ever sees it:
a "working" fix that opens 0.0.0.0/0 is not a fix. cfn-guard is the natural tool for
template-shaped input, but our gate evaluates remediation-plan JSON (a list of EC2 revert
operations), and bundling an arm64 binary into Lambda adds build friction for ~6 rules.

## Decision
`src/shared/policy.py`: a pure-Python rule set, unit-tested with pass and violation cases,
stamped with POLICY_VERSION which is recorded in every gate ledger entry.

The load-bearing rule is **converge-only, verified independently of the planner**. For every
op the gate reconstructs the state it would produce, in the baseline snapshot's own canonical
form (reusing `shared.baseline`, the intent oracle — never `plan.build`), and asserts that
state is present in / equal to the baseline for that exact resource and field: an authorize
adds only a rule already in that SG's baseline; a revoke removes only a rule absent from it; a
create/replace route sets only the baseline target; modify_vpc_attribute sets only the
baseline value; ENI groups equal the baseline set. A tampered or buggy op that targets a
non-baseline value is therefore *caught*, not reproduced — the anti-tautology property a
rebuild-and-compare check fails to provide (that earlier version compared the planner's output
against a second call to the same planner and could never fail; see POLICY_VERSION 1→2).

Because an authorize/create must match that specific resource's baseline, world-open rules
(0.0.0.0/0 or ::/0) that aren't already in the baseline are rejected as a direct consequence —
per-SG and per-direction, not by an account-wide heuristic. A completeness rule additionally
requires every drifted field to be addressed (no plan may leave residual drift). Supporting
rules: lab-resource-only, IGW-only default routes, bounded op count, and a single explicit
allowlist escape hatch for pre-approved world-open authorizes.

## Consequences
- The gate is deterministic, reviewable in one screen, and versioned in git — the properties
  cfn-guard would have given us, without the binary.
- If the rule set ever grows template-shaped (e.g. validating full stack updates), revisit
  cfn-guard.
