# Security posture

This platform *acts* on a live network, so it was audited adversarially: three parallel
review passes (IAM/STS/gate/denial-of-wallet; trust boundaries/injection/auth;
infra/secrets/supply-chain) against a deliberately hostile threat model — an attacker who
already has some foothold in the account. ~30 findings resulted; the material ones are fixed
and cross-referenced below. This file is the honest register: what was fixed, and what is a
*documented, deliberate* accepted risk rather than an oversight.

## What the audit found and fixed

| Severity | Finding | Fix | Ref |
|---|---|---|---|
| CRITICAL | Policy gate was a tautology — it compared the planner's output to a second call of the same planner, so it could never fail | Gate now verifies each op **converges to the recorded baseline** independently of the planner; a wrong-target op is caught, not reproduced | ADR 0004, `policy.py` |
| CRITICAL | `CONFIG#BASELINE`/`MODE`/`ALLOWLIST` (the definition of "correct") writable by every Lambda role | Config is admin-write-only; runtime writes IAM-scoped to `INCIDENT#*`; RA counter moved to its own key | ADR 0010 |
| HIGH | Detector loop-guard skipped any actor ARN *containing* `netops-remediation-` (attacker-forgeable session name) | Exact assumed-role-ARN prefix match | ADR 0010, `detector` |
| HIGH | Permissions boundary region-scoped, not lab-scoped — permitted mutating production network resources | Tag-scoped (`Project=agentic-netops`) + explicit VPC ARN for `ModifyVpcAttribute` | ADR 0010 |
| HIGH | `no-world-open` gate rule was account-wide and IPv4-only | Subsumed by per-op/per-SG converge check; IPv6 (`::/0`) now captured and guarded | ADR 0004, `policy.py`/`baseline.py`/`plan.py` |
| HIGH | RA budget monotonic → silent permanent verification degradation | Cap lowered to 30 ($3) + CloudWatch alarm on skip | ADR 0005 |
| MED | Detector create-incident + start-execution not atomic → stranded incident black-holes future events | Idempotent recoverable StartExecution on retry | `detector` |
| MED | Approval bound to a hash the console never validated (tampered `plan_ops`) | API re-hashes shown `plan_ops` against approved `plan_hash` at approval; console surfaces the hash | `api`, `ui` |
| MED | No gate re-check at the privileged moment | Executor independently re-runs the gate against a fresh baseline before assuming creds | `executor` |
| MED | Partial apply could leave a half-remediated network | Safe-first op ordering + existing SFN-failed alarm | `plan.py` |
| MED | Prompt-injection could steer the human approver via unverified AI text | Structural-only diff to the LLM (no attacker free text); AI narrative quarantined in the console | `model_provider.py`, `ui` |
| MED | S3 buckets lacked TLS-only deny; CloudTrail log-file validation off; DynamoDB no PITR/deletion-protection; no MFA capability; CORS `*`; no security headers | All added | `template.yaml` |
| LOW | `states:SendTask*` and Bedrock IAM broader than needed | Scoped to the one state machine / the Nova family | `template.yaml` |

Verified clean (no fix needed): the console uses `textContent` on every DOM sink (no XSS);
`task_token` is never logged nor returned by the API; no secrets in logs, CI, or compose;
poll loops are bounded; `consume_ra_budget` is genuinely fail-closed; the RemediationRole
trust policy admits only the executor; CI is genuinely credential-free.

## Autonomy-tier attack surface (auto-execute path, ADR 0011/0012)

Adding auto-execution (no human) made the tier classifier security-relevant. Analyzed
adversarially; each vector and its neutralization:

- **A1 — attacker forces LOW tier to get auto-execution.** Neutralized three ways: the gate
  still bounds every op to converge-to-baseline (worst forced outcome = a self-healing
  restore); `tier.decide` is deterministic + fail-closed (default MEDIUM; any
  revoke/delete/world-open-ingress/multi-resource/unknown/oracle-fail escalates); and LOW
  requires *all* ops additive. Covered by `test_redteam.py::test_B/G`.
- **A2 — auto-exec as a timing/topology oracle.** The diff + Reachability Analyzer run for
  *every* incident regardless of tier; the veto delay is a fixed 60s. No new leakage.
- **A3 — denial-of-wallet via drift flapping.** Bounded by the RA hard cap + alarm, MAX_OPS,
  pre-PROVE correlation coalescing, one-execution-per-incident, and the veto lets an operator
  cancel a storm. Residual (many bounded incidents) is under the budget alarm.
- **A4 — masking a real change inside a low-tiered burst.** Gate completeness reverts the
  whole diff; tier sees the whole diff (any tightening/multi-resource ⇒ not LOW); correlation
  only coalesces pre-PROVE, so post-snapshot drift gets its own incident + tier.
- **A5 — compromised console suppresses the veto.** Suppression only lets a converge-to-
  baseline restore proceed (benign); MEDIUM/HIGH still need positive approval.
- **A6 — stuck token in AUTO_EXEC_PENDING.** `TimeoutSeconds:60` + `Catch States.ALL` bound the
  wait, and **every** terminal state clears `task_token` — including `MarkFailed`, which
  originally did not (`tests/test_statemachine.py::test_all_non_executing_terminals_clear_the_task_token`
  now enforces it).
- **A7 — double-execute.** `waitForTaskToken` resolves exactly once; both proceed-outcomes
  funnel into a single `MarkExecuting`; `Execute` has no Retry and re-checks hash + gate. A late
  cancel gets `TaskTimedOut`/`TaskDoesNotExist`/`InvalidToken` → 409 (originally only the first
  was caught, so the other two surfaced as 500s). Covered by `test_statemachine.py` and
  `test_api.py`.
- **A8 — two-party bypass via a first-approver race.** The gap between the first
  `SendTaskSuccess` and `AWAITING_SECOND_APPROVAL` is seconds wide, and `first_approver` was
  written unconditionally — so a click landing in that gap could overwrite it and let one human
  satisfy both parties. The slot is now claimed with a conditional write
  (`ddb.claim_first_approver`): takeable exactly once, second claim → 409.

The standing `tests/test_redteam.py` suite re-checks A1/A3-family blocks plus plan-tampering,
replayed approvals, two-party bypass, kill-switch enforcement, and ledger tampering on every CI
run — nine attacks, each asserting the block, not the happy path.

## Regressions found by live testing, and why the test suite missed them

Recorded because the *gap* matters more than the bugs. Both were caught by driving the real
HTTP API against the deployed stack — neither could have been caught by the unit suite or the
9-class eval.

**1. Narrowing `states:SendTask*` silently denied every approval.** An audit flagged the
original `Resource: !Ref IncidentStateMachine` on `SendTaskSuccess`/`SendTaskFailure` as a
critical deny. That was a false positive — it demonstrably worked. But "hardening" it to
`Resource: "*"` plus a `states:StateMachineArn` condition *did* break it: that condition key
does not apply to these actions, so IAM denied implicitly and **every approve, reject and veto
returned 500**. These actions are authorized by the callback **token**, not by a resource ARN —
the token is unguessable, single-use, and only ever minted by this state machine, and that is
the security boundary. `tests/test_iam_parity.py::test_sendtask_grant_is_not_narrowed_into_a_silent_deny`
now fails if anyone narrows them again.

*Why nothing caught it:* the eval harness completes task tokens **directly with admin
credentials**, so it never exercises the API's approval path. That caveat was already written
down in `docs/evals.md` — and it turned out to be load-bearing. Unit tests didn't catch it
either, because they stub the Step Functions client and so never evaluate IAM. **Any change to
the `SendTask*` grant must be verified by an approval through the API.**

**2. `chaos.py --restore` raised incidents for its own cleanup.** The restore path mutates with
the *caller's* identity, not the RemediationRole the detector deliberately ignores, so the
platform correctly saw the cleanup as drift — and PROVE could snapshot mid-restore and find
partial drift, producing a real incident for a half-restored lab. Now wrapped in maintenance
mode with a CloudTrail-flush wait (the same trick `deploy_lab.ps1` uses, ADR 0002). Note the
wait is required: suppression has to outlast CloudTrail *delivery*, not just the last API call.

**3. Two-party approval was unreachable as documented.** Segregation of duties blocks an
approver mapped to the drift-causer. Because `chaos.py` runs as the account admin, the operator
mapped to that admin ARN is blocked from approving *every* seeded fault — leaving one eligible
approver where two are required. A HIGH-tier incident could never be approved. The fix is
operational, not code: **two non-admin operators**, documented in the README.

## Third pass: the identity & authorization perimeter

The first three audits all examined what happens *after* a valid JWT arrives. This pass probed
the perimeter itself against the **deployed** stack.

**Confirmed holding** (live, read-only): unauthenticated, malformed-token, `alg=none`, and
identity-forging-header requests all 401 at the gateway authorizer; CORS echoes only the
CloudFront origin and refuses others; both S3 buckets have all four public-access blocks plus
TLS-only denies; `RemediationRole` is assumable **only** by the executor — not even the account
admin can assume it; no role carries `AdministratorAccess`; the console has no XSS sink (every
DOM write is `textContent`); no secrets in the repo, and `ui/config.js` is genuinely ignored.

| Severity | Finding | Fix |
|---|---|---|
| HIGH | **SoD guarded approval only** — the drift-causer could reject or veto the repair for their own change. When the drift *is* the security hole, blocking the fix preserves it, and the ledger records it as a routine decision | Recusal from every decision (approve/reject/cancel) | ADR 0016 |
| MED | **Actor identity failed open** — a token without an `email` claim yielded the actor string `"unknown"`, which flowed into the SoD comparison, `first_approver`, and the ledger as the approver of a live network change | 403 on any POST without an attributable caller; guard is route-prefixed so future POST routes inherit it |
| MED | **`GET /verify` reported tampering for a nonexistent id** — returned 200 `{valid: false, first_break_seq: 1}`, indistinguishable from a real broken chain, in the one tool whose job is telling those apart | 404 when the incident does not exist |
| MED | **`governance.store_token` validated nothing** — accepted any `incident_id` and any `wait_status` string, then overwrote `task_token` + `status`. Only IAM stood between a bad ASL edit and a cross-incident token overwrite | Envelope validation: incident must exist, `wait_status` must be in `status.AWAITING_DECISION` |
| MED | **Username enumeration** — `PreventUserExistenceErrors` unset, so Cognito distinguished unknown-user from wrong-password on an unauthenticated endpoint | `ENABLED`; verified live that both now return identical `NotAuthorizedException` |
| MED | **No API access logging** — a denied 403 (an SoD recusal, a two-party bypass attempt) left no durable trace beyond a 7-day Lambda log written only if the handler happened to log it | Access log group with the caller's email per request, plus a metric filter and alarm on repeated 403s |
| LOW | **30-day refresh tokens** on a console that can mutate a live network — and the console discards the refresh token anyway | 24 hours |
| LOW | **Password policy was length-only** (12 chars, no character classes) | upper + lower + digits required |
| LOW | **No CSP / Permissions-Policy** on a page that renders LLM-authored text | Both added; see the `unsafe-inline` note below |
| LOW | **CI had no `permissions:` block** (GITHUB_TOKEN inherited the repo default) and pinned all actions to mutable major tags | `contents: read`, SHA-pinned at the versions already proven green, `timeout-minutes` |

Two of these deserve their honest ceilings stated:

- **The CSP carries `'unsafe-inline'`**, because the console is a single inline `<script>` +
  `<style>`; that concedes most of CSP's XSS value. What it does buy is `connect-src`: the page
  holds a JWT that can approve live network changes, and outbound calls are now pinned to API
  Gateway and Cognito, so injected script cannot exfiltrate that token to an arbitrary origin.
  `object-src`/`base-uri`/`form-action`/`frame-ancestors` are locked regardless. Upgrade path:
  extract the script and style to files and drop `unsafe-inline`.
- **`connect-src` uses a `*.execute-api` host wildcard**, not this stack's API id, because naming
  the id creates a genuine CloudFormation cycle (CSP → HttpApi → CORS → distribution domain →
  CSP). Exfiltration would require an attacker-controlled API Gateway in the same region.

### The boundary check is finally runnable — and the documented procedure was impossible

`SECURITY.md` demanded (and ADR 0010 still listed as open) "assume `RemediationRole`, attempt a
mutation on an untagged resource, expect `AccessDenied`". That procedure **cannot be executed**:
the trust policy admits only `ExecutorFunctionRole`, so no operator can assume the role. The
control being correct is what made its own verification impossible.

`scripts/verify_boundary.py` decomposes the claim into three parts that *are* each provable,
read-only, mutating nothing and costing nothing:

1. **Policy logic** — every mutating action simulated against **its own resource type** (an
   important detail: `ec2:CreateRoute` on a security-group ARN denies regardless of tags, which
   would look like the boundary working while testing nothing), with explicit tag context:
   correct tag ⇒ allowed; wrong tag, absent tag, wrong region ⇒ denied. Plus the ARN-pinned
   `ModifyVpcAttribute` exception: the lab VPC allowed, another VPC denied.
2. **Live tagging** — every lab resource the planner can target actually carries
   `Project=agentic-netops`. A correct policy guarding mistagged resources would still fail.
3. **Trust** — the role is not assumable by the caller running the check.

**Result: 18/18 pass.** Together with the recorded 9/9 end-to-end remediation runs, this closes
the open item without weakening anything in order to test it.

## Accepted risks (deliberate, not oversights)

- **Encryption at rest uses AWS-owned keys, not a CMK.** The ledger, the SNS anchor topic and
  the CloudTrail bucket are all encrypted, but a customer-managed key is the enterprise
  expectation for a tamper-evidence store — it would let a key policy separate "may write
  incidents" from "may rewrite history", which is exactly the separation the hash chain is
  trying to establish. Not done because each CMK is ~$1/month and this project's hard
  constraint is a **$0.00 idle bill**. *Close later:* a CMK on the table with a key policy that
  denies the runtime roles `kms:ReEncrypt*`/`kms:Decrypt` on historical items.
- **The tag is a trust boundary with no tag governance.** `RemediationRole` may mutate anything
  tagged `Project=agentic-netops`. `RemediationRole` itself cannot tag (no `ec2:CreateTags`
  anywhere), but this is a standalone account with **no AWS Organization**, so no SCP can
  restrict who else may apply that tag — an admin could tag a production resource into scope.
  *Close later (the production answer):* an SCP denying `ec2:CreateTags` for
  `aws:RequestTag/Project = agentic-netops` outside a break-glass role.
- **`USER_PASSWORD_AUTH` is enabled and SRP is not.** The console posts `InitiateAuth` directly
  from the browser, so passwords reach Cognito rather than being proved by SRP. Cognito
  rate-limits the endpoint and enumeration is now closed. *Close later:* SRP, or the Cognito
  hosted UI with an OIDC redirect.
- **No GuardDuty, AWS Config, or WAF.** All three are metered; their absence is a cost decision
  rather than an oversight. The origin is private (OAC) and Cognito-gated, and the detector's
  own CloudTrail consumption covers the change-detection role Config would play here.
- **Cognito advanced security (threat protection) is off** — no compromised-credential
  detection or adaptive auth. It moves the pool to a paid tier.

- ~~**No segregation of duties on approval.**~~ **CLOSED (ADR 0013):** HIGH-tier incidents
  require two distinct approvers (maker-checker); an approver mapped (via `CONFIG#APPROVERS`)
  to the `drift_actor` is blocked. *Residual:* an unmapped external drift actor can't be
  proven to collude, so it's allowed but surfaced in the console.
- **Ledger crash-tail reads as tampered.** A crash between the head advance and the entry
  write leaves a detectable head/entry mismatch (`verify_ledger` → invalid) — a false positive
  for tampering, resolved by inspection. Detected-benign, not silent (ADR 0014).
- **Ledger anchoring is SNS out-of-band, not independent notarization.** Implemented and
  enforced on every terminal outcome (ADR 0014), but an emailed head is only as good as the
  mailbox. *Close later:* QLDB / S3 Object Lock / an external timestamping service.
- **Autonomy kill-switch is evaluated at plan-time.** `CONFIG#AUTONOMY=manual` bumps LOW→MEDIUM
  when the plan is generated; an incident already in its veto window isn't retroactively
  paused (cancel it manually). Acceptable — the window is 60s.
- **MFA is OPTIONAL, not enforced.** TOTP is available; enforcement is off so the one-step
  demo login keeps working. *Close later:* `MfaConfiguration: ON` + TOTP challenge handling
  in the console login.
- **No CloudFront WAF.** The origin is private (OAC) and Cognito-gated; a WAF is cost for
  marginal benefit at lab scale. *Close later:* attach a managed rule set if the console goes
  multi-tenant/public.
- **Dependencies pinned by range, not hash/lockfile.** CI is offline and credential-free, so
  the supply-chain blast radius is small. *Close later:* a hash-pinned lockfile.
- **RA cap is project-lifetime, not a rolling window.** Alarmed on exhaustion; reset is a
  one-line edit. A scheduler is YAGNI for a lab.
- **Bedrock IAM allows the Nova family, not one pinned model.** The eval-gate is the real
  control on which model ships; IAM narrowing to Nova blocks the pricier non-Nova models.
  *Close later:* pin to the exact `ModelId` ARN.
- **CloudTrail is single-region.** Correct by design — the detector consumes only in-region
  EC2 management events.

## Live verification after deploy — now scripted

Two things cannot be proven by reading code or running the unit suite. Both are now runnable:

```powershell
.venv\Scripts\python scripts\verify_boundary.py    # boundary: policy logic + live tags + trust
```

**And the standing rule that a green eval does not cover:** any change touching the approval path
(`states:SendTask*` IAM, the API handler's guards, the governance token writer) must be verified
by a real approve/reject/veto **through the HTTP API**. `scripts/evaluate.py` completes task
tokens directly with admin credentials, so a 9/9 run has already coexisted with every console
approval returning 500. See the regression register above and `docs/evals.md`.

Residual per-action caveat: `aws:ResourceTag` support varies by EC2 action, so an `AccessDenied`
on a *legitimate* lab remediation during an eval regression still means that action needs the
ARN-scoping fallback rather than the tag condition (as `ModifyVpcAttribute` already does).
