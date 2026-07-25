# Conventions

Short, and all of it enforced somewhere — a convention nothing checks is a suggestion.

## Error handling: raise to stop the loop, swallow to degrade

The policy is deliberate per component, not ad hoc:

| Component | Policy | Why |
|---|---|---|
| `executor` | **raises** | A failed mutation must fail the workflow so VERIFY never runs against a half-applied plan. `Execute` has no `Retry` — retrying a partial apply could double-apply. |
| `prove`, `planner` (gate path) | **raises** | If intent can't be established or the gate can't run, there is nothing safe to do. |
| `diagnose`, `planner` (LLM rationale) | **swallows + logs** | The narrative is advisory. A Bedrock outage must not stop a remediation the deterministic layer already decided. |
| `detector` | **swallows per record**, reports partial batch failure | One malformed SQS message must not block the rest of the batch; SQS retries just that message. |
| `api` | **catches all → 500** | An HTTP boundary never leaks a stack trace. Post-commit failures (ledger append after a token send) log and continue rather than turning a successful approval into an error. |
| `anchor_ledger` | **best-effort** | The chain is already durable in the table; failing to publish the out-of-band copy must not fail an otherwise-resolved incident. |

Every broad `except` carries `# noqa: BLE001`. That is meaningful because `BLE` is *enabled* in
`pyproject.toml` — so each one is a reviewable decision rather than an accident.

## Deliberate shortcuts are marked

`# ponytail:` marks a known-ceiling simplification, naming the ceiling and the upgrade path.
Current ones: the ledger's single-item optimistic lock, the detector's linear correlation scan,
the fixed RA poll ceiling, and the STS session-name truncation. If you remove the ceiling,
remove the comment.

## Single sources of truth

Duplication across the Python/ASL/PowerShell/JS boundary has no type checker, so each shared
vocabulary has exactly one home **and a parity test**:

- incident statuses → `shared/status.py` (`tests/test_statemachine.py` asserts the ASL only
  writes declared members)
- mutating EC2 actions → `shared/sts_scope.ACTION_MAP` (`tests/test_iam_parity.py` asserts the
  gate allowlist and the template IAM agree)
- fault classes → `shared/classify.py` (parity test asserts every class has an oracle policy)
- world-open CIDRs → `shared/policy.WORLD_OPEN` (imported by `tier.py`)
- canonical config form → `shared/baseline.canonical_*` (the gate speaks the oracle's language)

## Testing

Deterministic logic lives in `src/shared/` and is unit-tested directly; handlers stay thin and
are tested through their `lambda_handler` against moto. A test that re-implements the rule it
claims to verify is worse than no test — `tests/test_redteam.py::test_H_kill_switch_forces_human`
exists in its current form because the earlier version did exactly that and stayed green.

CI is credential-free by construction: `tests/conftest.py` installs fake credentials and strips
`AWS_PROFILE`, so a test cannot reach real AWS even by accident.
