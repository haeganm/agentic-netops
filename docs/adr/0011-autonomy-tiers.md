# ADR 0011: Deterministic autonomy tiers (auto / approve / two-party)

**Status**: accepted (2026-07-24)

## Context
"Always require a human approval" is safe but crude — it wastes a human on a routine
restore and treats a world-open exposure the same as re-adding a deleted rule. A mature
governed system varies the oversight to the risk.

## Decision
`src/shared/tier.py` computes a deterministic tier per incident from the fault class, the
ops, the diff, and the oracle verdicts already in the ledger — never the LLM. Computed in the
planner after the gate, so it's reproducible from the ledger.

- **LOW** (auto-execute with a veto window, ADR 0012): every op is purely additive/restorative
  (authorize / create-route / create-nacl-entry / enable-dns), gate PASS, all applicable
  oracles clean. Routine restores that can only *grant* intended access.
- **MEDIUM** (single human approval): any op removes/tightens or changes posture
  (revoke / delete / replace-association / modify-eni-groups).
- **HIGH** (two-party approval, ADR 0013): low confidence (unknown `config-drift`), broad
  blast radius (>1 resource or >1 section), a **security-group ingress open to the world**
  (the classic inbound exposure — a route or egress to 0.0.0.0/0 is routine and does not
  escalate), or any oracle failure/skip/disagreement.

**Fail-closed:** the default is MEDIUM and LOW is granted only when *every* signal is clean,
so a misclassification can only ever *over*-escalate (demand more oversight), never under. The
tier changes only *who signs off* — the policy gate still bounds every op to converge-to-
baseline, so even a forced auto-exec can only restore declared-good state.

A global kill-switch `CONFIG#AUTONOMY {mode:"manual"}` (admin-write-only) bumps any LOW back
to MEDIUM, halting all no-human execution instantly.

## Consequences
- Across the 9 fault classes: routine restores (sg-ingress-removed, sg-egress-removed,
  route-deleted, dns-disabled) → LOW; posture changes (route-blackholed, nacl-deny,
  rtb-assoc-swapped, sg-swapped-on-eni) → MEDIUM; sg-open-world (+ unknown/multi/oracle-fail)
  → HIGH. A clean, defensible spread.
- The auto-execute path is a new attack surface, analyzed in docs/SECURITY.md (A1–A7) and
  covered by the standing red-team suite. The tier reasons are ledgered and appear in the
  compliance evidence export.
