# ADR 0015: Per-incident compliance evidence export

**Status**: accepted (2026-07-24)

## Context
For a serious institution, "the platform fixed it" is not enough — an auditor needs to see,
per incident, that the change was authorized, minimally privileged, verified, overseen by a
human where required, within policy, and that the record itself hasn't been tampered with.
The platform already produces all of that evidence; it just needed to be assembled into the
language auditors use.

## Decision
`src/shared/evidence.py::build_report(incident_id)` maps one incident to six control
assertions, each backed by concrete evidence pulled from the META + ledger (pure read, no AWS
mutations, no LLM):

| Control | Evidence |
|---|---|
| change-authorized | tier + tier_reasons; the approval records (or the LOW-tier veto) |
| least-privilege | the recomputed per-incident STS session policy + the exact applied EXECUTE operations |
| verified | intent re-diff (0), Reachability Analyzer reachable before/after, data-plane probe |
| human-oversight | drift_actor, tier path taken, approver identities, SoD enforced |
| within-policy | gate POLICY_VERSION + verdict + violations |
| tamper-evident | `verify_ledger()` result (chain valid + head hash) |

Consumers: `GET /incidents/{id}/evidence` (JSON for the console), `GET /incidents/{id}/verify`
(the chain badge), and read-only scripts `compliance_export.py` (md/JSON) / `verify_ledger.py`.

## Consequences
- Every autonomous (or approved) remediation produces a regulator-ready evidence package on
  demand, and the tamper-evidence check (ADR 0014) is part of it — so the package attests to
  its own integrity.
- The export is derived, not stored: it always reflects the current ledger and re-verifies the
  chain at read time. No new data to keep in sync.
