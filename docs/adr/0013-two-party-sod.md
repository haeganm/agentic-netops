# ADR 0013: Two-party approval and segregation of duties

**Status**: accepted (2026-07-24)

## Context
The prior audit (docs/SECURITY.md) recorded "no segregation of duties on approval" as an
accepted risk. With autonomy tiers, HIGH-risk incidents now warrant the strongest human
control there is — maker-checker: the person who caused a change cannot be the one who
approves fixing it, and a high-risk fix needs two distinct people.

## Decision
- **Drift attribution.** The detector records `drift_actor` (the IAM ARN that caused the
  change) on the incident META, so every approval decision can be checked against who caused
  the incident.
- **Identity mapping.** Approvers authenticate as Cognito emails; drift actors are IAM/STS
  ARNs — different identity systems. `CONFIG#APPROVERS {map: {email: iam_arn}}` (admin-
  maintained, like BASELINE) bridges them. `_maps_to_drift(email, meta)` blocks an approval
  where the mapped ARN equals `drift_actor` (403).
- **Two-party (HIGH tier).** After the first approval the workflow enters
  `AWAITING_SECOND_APPROVAL` and requires a second token from a **distinct** Cognito identity
  (`actor != first_approver`, server-enforced on the persisted `first_approver`; 403 on the
  same user). Both approvals are ledgered with their party.
- All checks are server-side in `api._decide`; console hints are advisory only.

## Consequences
- Closes the "no SoD" accepted risk for the classes that matter (HIGH tier); MEDIUM keeps
  single approval; LOW auto-executes with a veto.
- **Residual, documented:** a `drift_actor` with no entry in `CONFIG#APPROVERS` (an external
  principal) can't be proven to collude, so it's allowed but surfaced prominently in the
  console. Recorded in docs/SECURITY.md.
- Demo needs a second Cognito operator + the `CONFIG#APPROVERS` map (seeded in Phase 6).
