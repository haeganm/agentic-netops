# ADR 0009: Per-incident session policies must cover every resource an action authorizes against

**Status**: accepted (2026-07-24)

## Context
The EXECUTE stage assumes RemediationRole with a per-incident session policy listing only
the approved plan's resources (effective perms = role ∩ boundary ∩ session policy). The
first eval pass surfaced three `UnauthorizedOperation` failures where the plan was correct
but the session policy was too tight — the tight policy correctly denying an ARN the action
needed but the plan didn't enumerate:

- `ec2:ReplaceRouteTableAssociation` authorizes against the **new** route table, the
  **subnet**, and the **current** route table (unknown until runtime).
- `ec2:ModifyNetworkInterfaceAttribute` (Groups) authorizes against the ENI **and every
  security group** being applied.

## Decision
`sts_scope.session_policy(ops, inventory)` computes the full authorization set per action,
not just the primary resource. Where a required resource can't be known before execution
(the current route table in an association swap), it scopes to the relevant lab-inventory
set (all lab route tables) — still bounded to lab-tagged resources, never `"*"`. Unit tests
assert the exact ARN set per action.

## Consequences
- This is the intended security posture *working*: a mis-scoped credential fails closed and
  loudly at execution, ledgered as an AccessDenied outcome — never a silent over-grant.
- The boundary and role stay at `"*"` within region; the session policy is the tight ring,
  and it is now correct for every fault class in the taxonomy.
- General lesson recorded for the portfolio: least-privilege for a mutating API means
  enumerating *all* resources in its authorization context, which AWS documents per action
  and which live testing is the only reliable way to confirm.
