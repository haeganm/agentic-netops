# ADR 0005: Reachability Analyzer spend is hard-capped in code

**Status**: accepted (2026-07-24)

## Context
VPC Reachability Analyzer is the impact oracle and the project's only meaningfully metered
API ($0.10/analysis). Budgets and alarms alert after the fact; the project's ≤$15 promise
needs a guarantee that holds even if the loop misbehaves.

## Decision
A DynamoDB item `LIMITS#RA / COUNTER {used, cap=30}` is consumed with an atomic
`ADD used 1` under `ConditionExpression: used < cap` before every StartNetworkInsightsAnalysis.
On ConditionalCheckFailed (including a missing item — fail-closed), the analysis is skipped,
the verdict is ledgered as `skipped-budget`, and the incident closes as
VERIFICATION_LIMITED instead of RESOLVED. Cap 30 bounds RA spend at $3.00 for the
project's life (aligned with the $2 budget alert). Oracle selection is policy-driven per
fault class, so RA only runs when the fault actually affects reachability.

The counter lives in its OWN partition (`LIMITS#RA`, not `CONFIG#`) so that IAM can scope
the single runtime writer (the oracles function) to exactly this key while leaving every
`CONFIG#*` item writable by no runtime role at all (see ADR 0010).

## Consequences
- Worst-case RA spend is a constant, not a hope. Raising the cap is a deliberate,
  git-visible edit.
- Incidents past the cap still complete the loop (intent + data-plane oracles) but are
  honestly labeled as less verified — and a CloudWatch alarm on the `ra_skipped_budget`
  log line fires the moment that starts happening, so degraded verification is never silent
  (the original design would have degraded quietly forever once exhausted).
- The cap is project-lifetime, not a rolling window; reset is a one-line edit to the
  counter item. A scheduler was judged YAGNI for a lab (see docs/SECURITY.md).
