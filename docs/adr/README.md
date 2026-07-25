# Architecture decision records

Read in this order for the shape of the system: **0001** (why a closed loop at all), **0003**
(what "intended state" means), **0004** (the gate that bounds every repair), **0011** (who has
to sign off), **0014** (why the record can be trusted).

| # | Decision | Why it matters |
|---|---|---|
| [0001](0001-closed-loop-control-system.md) | A closed-loop control system, not "an AI that fixes networks" | The thesis. Every stage has a deterministic oracle; the LLM is scored, never trusted |
| [0002](0002-two-stacks.md) | Lab network and platform are separate stacks | Platform redeploys can't disturb the drift target — and a mid-incident deploy became a feature (durable resume) |
| [0003](0003-baseline-differ-primary-intent-oracle.md) | Baseline snapshot differ is the primary intent oracle | CFN drift detection has coverage gaps; the differ has none. Drift = divergence from a captured baseline |
| [0004](0004-python-policy-gate.md) | The policy gate is versioned Python, checked independently of the planner | **Converge-only**: a repair can only restore declared state. Rewritten after the original was found to be a tautology |
| [0005](0005-ra-hard-cap.md) | Reachability Analyzer spend is hard-capped in code | The only metered oracle; the cap is a constant, not a hope. Exhaustion is alarmed, never silent |
| [0006](0006-cloudtrail-trail-required.md) | A write-only CloudTrail trail is required for detection | Live-verified: no trail → no EventBridge events, despite the docs implying otherwise |
| [0007](0007-ra-managed-policy-exception.md) | One deliberate AWS-managed-policy exception | RA's engine walks the graph with the caller's permissions; AWS owns that action list, not us |
| [0008](0008-ra-authority-ends-at-igw-egress.md) | RA's authority ends at IGW egress in a no-public-IP lab | Knowing precisely where an oracle *stops* being able to adjudicate, and labelling verification accordingly |
| [0009](0009-session-policy-multi-resource-authorization.md) | Session policies must cover every resource an action authorizes against | Found by a live eval: least-privilege failing *closed* on ARNs the plan didn't enumerate |
| [0010](0010-iam-least-privilege-hardening.md) | Key-scoped writes, tag-scoped remediation ceiling | Config is a trust boundary; the boundary is scoped to lab-tagged resources, not just the region |
| [0011](0011-autonomy-tiers.md) | Deterministic autonomy tiers (auto / approve / two-party) | Ask for a human *when it matters*. Fail-closed: misclassification can only over-escalate |
| [0012](0012-veto-window-inverted-timeout.md) | LOW-tier veto window via inverted-timeout task token | Human-*on*-the-loop: timeout means proceed, a cancel aborts. The one place a timeout is inverted |
| [0013](0013-two-party-sod.md) | Two-party approval and segregation of duties | The drift-causer can't approve their own fix; HIGH needs two distinct humans |
| [0014](0014-hash-chained-ledger.md) | Tamper-evident hash-chained decision ledger | Any alteration/insertion/deletion is detectable at an exact sequence number; the head is anchored out-of-band |
| [0015](0015-compliance-evidence-export.md) | Per-incident compliance evidence export | Six control assertions, each backed by concrete evidence — including the ledger's own integrity |

All are `accepted`. None is superseded, but two were **corrected** after being contradicted by
the code: 0004 (the gate was a tautology; now genuinely independent) and 0003 (it claimed a
post-VERIFY re-baseline that was never implemented, and shouldn't be). Both corrections are
recorded in the ADRs themselves rather than hidden — see `docs/SECURITY.md` for the audit that
found them.
