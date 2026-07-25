# ADR 0016 — Segregation of duties means recusal, not "cannot approve"

**Status:** accepted (2026-07-25) · supersedes the approve-only scope of ADR 0013

## Context

ADR 0013 introduced segregation of duties: an operator mapped (via `CONFIG#APPROVERS`) to an
incident's `drift_actor` may not approve its remediation. The check was implemented inside the
`if approve:` branch of `api/handler.py::_decide`, and `_cancel` had no check at all.

So the operator who caused the drift retained two powers over the outcome:

- **reject** the repair for their own change (MEDIUM/HIGH), and
- **veto** the auto-remediation of their own change during the LOW-tier window.

The implicit reasoning was that rejection is safe because it mutates nothing. That holds only
when the drift is an outage. It fails when **the drift is the security hole**:

> An insider adds `0.0.0.0/0:22` to a lab SG. The platform detects it, proves it, classifies it
> `sg-open-world`, generates the exact revoke, and routes it to HIGH tier. The insider then
> rejects their own remediation. The hole stays open, and the decision ledger records an
> ordinary-looking `rejected by <them>` — the governance system has been used to *preserve* the
> compromise, and the audit trail makes it look procedural.

The LOW-tier variant is the same shape: break something, veto the self-heal, and the outage you
caused persists behind what reads as a legitimate operator veto.

In audit and financial-controls usage, segregation of duties means **recusal from the
decision** — not merely the loss of the ability to say yes. A party with an interest in the
outcome is removed from the decision entirely, in both directions.

## Decision

`_maps_to_drift` is evaluated on **every** decision route: approve, reject, and cancel. The
drift-causer receives 403 with an explanation naming the verb they attempted.

Two checks remain deliberately approve-only, because they are meaningless for a rejection:

- **plan-integrity re-hashing** — a reject consents to no plan, so there is no hash to bind.
- **two-party distinctness** — a rejection has no second party to be distinct from.

## Consequences

**Recusal costs nothing operationally.** This was the decisive point:

| Tier | Causer rejects (before) | Causer recused (now) |
|---|---|---|
| MEDIUM/HIGH | incident REJECTED, network stays drifted | no decision → incident EXPIRES, network stays drifted — **same end state** |
| LOW | auto-heal cancelled, drift persists | veto refused → **repair proceeds**, drift removed |

So the change never removes an outcome the causer could legitimately need; on LOW it strictly
improves the result. If the causer genuinely believes the repair is wrong, the escalation path is
another operator — which is the entire point of the control.

**Operational requirement.** Two-party approval now needs **two non-admin operators**. Because
`chaos.py` runs as the account admin, an operator mapped to that admin ARN is recused from every
seeded fault, which previously left too few eligible approvers for a HIGH-tier incident to ever
complete. Documented in the README.

**Residual risk (unchanged from ADR 0013).** An *unmapped* drift actor cannot be tied to any
operator, so recusal cannot fire; the console surfaces the `drift_actor` so a human can notice.
The map is the trust anchor, and it is admin-write-only (ADR 0010).

## Verification

- `tests/test_api.py::test_sod_blocks_reject_by_the_drift_causer`,
  `::test_sod_blocks_veto_by_the_drift_causer`, and
  `::test_recusal_does_not_block_a_different_operator` — the last one matters most: it asserts
  the legitimate path still works, since a control that blocks everyone is not a control.
- Live, through the real HTTP API: causer's approve **and** reject both 403; a different operator
  approves and the incident resolves. Separately, the causer's veto on a LOW-tier incident is
  refused and the self-heal proceeds to RESOLVED. Recorded in `docs/evals.md`.
