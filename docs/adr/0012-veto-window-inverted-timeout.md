# ADR 0012: LOW-tier veto window via inverted-timeout waitForTaskToken

**Status**: accepted (2026-07-24)

## Context
A LOW-tier remediation (ADR 0011) should auto-execute, but "human-on-the-loop" — an operator
must be able to *stop* it, even if they don't have to *start* it. That's a veto window: a
countdown during which a cancel aborts, and silence proceeds.

## Decision
`VetoWindow` is a `lambda:invoke.waitForTaskToken` state with the semantics **inverted**
relative to the approval waits:
- `TimeoutSeconds: 60` and `Catch States.Timeout -> MarkExecuting` — **no cancel means
  proceed** (the opposite of the approval waits, where timeout -> Expired).
- An operator's Cancel calls `SendTaskFailure(error="Cancelled")` -> `Catch Cancelled ->
  MarkCancelled` (terminal, clears token).
- `Catch States.ALL -> MarkFailed` and the fixed timeout bound the wait, so the token can
  never get stuck in `AUTO_EXEC_PENDING`.
- A `SendTaskSuccess` (optional "execute now" button) also -> `MarkExecuting`.

Both "proceed" outcomes (timeout, execute-now) funnel into the single `MarkExecuting` ->
`Execute`. Because a `waitForTaskToken` state resolves **exactly once** (timeout XOR token),
and `Execute` has no Retry and re-checks plan-hash + gate, there is no path that executes
twice — a cancel arriving after the window closed simply gets `TaskTimedOut` (409 at the API).

## Consequences
- LOW incidents self-heal without a human, but any operator watching the console has 60
  seconds to veto — the strongest "autonomous yet controllable" story, and the best demo.
- The inversion is the one place the timeout means the opposite of everywhere else; it is
  called out in `tests/test_statemachine.py::test_veto_window_timeout_inversion` so it can't
  silently regress.
- The kill-switch (ADR 0011) removes LOW entirely (bumps to MEDIUM), so the veto path can be
  globally disabled without a deploy.
