# ADR 0001: A closed-loop control system, not an AI that fixes networks

**Status**: accepted (2026-07-24)

## Context
AI investigation of cloud incidents is commoditized (Amazon Q Developer investigates and
suggests). The hard, differentiating engineering is everything around the model: proving a
diagnosis, bounding what a fix may do, and verifying the fix actually restored intent.

## Decision
The system is a deliberately engineered closed loop — DETECT → PROVE → MEASURE →
GENERATE-REPAIR → APPROVE → EXECUTE → VERIFY — where every stage has explicit entry/exit
criteria and an owning deterministic oracle. The LLM is one bounded, env-swappable component:
it drafts the diagnosis narrative and repair rationale. Its fault-class hypothesis is scored
against the deterministic diff classification and ledgered, but control flow never depends on
it. The LLM proposes; deterministic systems dispose.

## Consequences
- Every claim the platform makes ("diagnosed", "repaired", "safe") is attributable to a
  deterministic oracle, not model output.
- The model can be downgraded, upgraded, or removed without changing loop semantics —
  releases are eval-gated (ADR pattern from v1).
- The ledger records stage transitions and oracle verdicts, making every incident replayable.
