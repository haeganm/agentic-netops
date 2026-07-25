# Evals

The eval suite (`scripts/evaluate.py`) seeds all 9 labeled fault classes through the REAL
pipeline — chaos seed → CloudTrail → detect → the full loop — and scores each.

**Scope caveat, stated plainly:** the harness is tier-aware (LOW classes auto-execute through
the veto window; HIGH classes need two token completions) and it completes Step Functions task
tokens **directly**, not through the console API. So it validates *the loop*, not the API's
authorization controls — plan-integrity re-hashing, segregation of duties, and two-party
distinctness are covered by `tests/test_api.py` and `tests/test_redteam.py` instead, and were
additionally verified live (403 on a same-user second approval).

Scores:

- **det_correct** — deterministic classifier matched the label (harness sanity; must be 9/9)
- **diagnosed** — the LLM's fault-class hypothesis matched the label (the scored, non-authoritative signal)
- **remediated** — incident reached RESOLVED: intent re-diff empty + applicable oracles green
- **mean MTTR** — seed → resolved wall clock, including CloudTrail delivery latency
- **cost** — RA analyses × $0.10

Release gate (`scripts/release_model.ps1`): a candidate `ModelId` deploys only if
**diagnosed ≥ 8/9 and remediated = 9/9**. Remediation must be perfect because it never
depends on the LLM — a remediation failure is a platform bug, not a model regression.

| Run (UTC) | Model | det | diagnosed | remediated | mean MTTR | notes |
|---|---|---|---|---|---|---|
| 2026-07-24 first pass | nova-micro | 9/9 | 6/9 | 5/9 | ~89s | 4 failures, two root causes (below) |
| 2026-07-24 after fixes | nova-micro | 9/9 | 6/9 | **9/9** | ~85s | the 4 failed classes re-run green (77/70/97/77s) |
| 2026-07-24 post-security-hardening | nova-micro | 9/9 | 6/9 | **9/9** | ~90s | regression after the audit remediation: the tag-scoped remediation boundary honored all 9 action types (zero AccessDenied), and the independent gate + executor gate re-check passed every legitimate plan. One gate false-positive (association-swap completeness) was caught by this very regression and fixed. |

Deterministic classification is 9/9 every run — it drives control flow. Remediation went
5/9 → 9/9 once the two governance bugs below were fixed; it never depended on the LLM.

The LLM's diagnosis agreement is 6/9 (Nova Micro misses sg-open-world, rtb-assoc-swapped,
sg-swapped-on-eni). That is the scored, non-authoritative signal — and it is **below this
project's own release gate** of diagnosis ≥ 8/9, so Nova Micro would be blocked from
release by `release_model.ps1`. That is the eval harness working as designed: a bigger
model is the documented upgrade path, and because remediation is 9/9 independent of the
model, the loop is safe to run in the meantime.

The first full pass surfaced 4 remediation failures, all from two root causes — exactly
what a real eval suite is for:

1. **Route classes (route-deleted, route-blackholed)**: VERIFY's RA path
   AnchorEniPublic→IGW is unreachable even at baseline because the $0 lab has no public
   IPs (RA correctly requires one for internet egress — `IGW_PUBLIC_IP_ASSOCIATION_FOR_EGRESS`).
   The repair was provably correct (intent re-diff empty); the oracle was mis-scoped.
   Fix: route classes verify by intent + CFN drift; RA dropped for them (ADR 0008).
2. **Association / ENI-modify (rtb-assoc-swapped, sg-swapped-on-eni)**: the per-incident
   STS session policy granted only the primary resource ARN, but
   `ReplaceRouteTableAssociation` also authorizes against the subnet, and
   `ModifyNetworkInterfaceAttribute` against each security group. This is the tight
   session policy doing its job — denying an ARN the plan needed but didn't list. Fix:
   `sts_scope.session_policy` emits the full ARN set per action, with unit tests.

Deterministic classification and the policy gate were correct on all 9 from the start;
the LLM's 6/9 diagnosis agreement is the scored-but-not-trusted signal, and remediation
never depended on it.
