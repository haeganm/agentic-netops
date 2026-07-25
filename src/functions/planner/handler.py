"""GENERATE-REPAIR: deterministic converge-to-baseline plan + policy gate.
The LLM contributes only the human-readable rationale (best-effort, never blocking).
"""
import json

from shared import classify, ddb, ledger, plan, policy, tier
from shared.log import log


def lambda_handler(event, context):
    iid = event["incident_id"]
    diff = event["diff"]

    cfg = ddb.get_config("BASELINE")
    base = json.loads(cfg["snapshot"])
    inventory = json.loads(cfg["inventory"])
    ops = plan.build(diff, base)
    gate = policy.evaluate(ops, diff, base, inventory)
    phash = plan.plan_hash(ops)

    # Deterministic autonomy tier from the diff + ops + the oracle verdicts already ledgered
    # this incident. Reproducible from the ledger; the LLM has no say (ADR 0011).
    # Skip truncated entries: ledger.append clamps payloads at MAX_PAYLOAD, and a sliced
    # JSON string would raise here -- which used to fail the planner on exactly the widest
    # (highest-severity) drift. A truncated verdict is dropped, never half-parsed.
    verdicts = [json.loads(e["payload"]) for e in ddb.query_ledger(iid)
                if e["kind"] == "oracle_verdict" and not e.get("truncated")]
    fault_class = classify.classify(diff) if diff else "config-drift"
    autonomy_tier, tier_reasons = tier.decide(fault_class, ops, diff, verdicts)
    # global kill-switch: force any LOW auto-exec back to a human (admin-only CONFIG#AUTONOMY)
    if (ddb.get_config("AUTONOMY") or {}).get("mode") == "manual" and autonomy_tier == tier.LOW:
        autonomy_tier = tier.MEDIUM
        tier_reasons = [*tier_reasons, "kill-switch: autonomy=manual -> human required"]

    rationale = ""
    try:  # best-effort narrative; the gate verdict stands regardless
        from shared import model_provider
        diagnosis = event.get("diagnosis", {}).get("summary", "")
        rationale = model_provider.explain_repair(diagnosis, ops)
    except Exception as e:  # noqa: BLE001
        log("rationale_skipped", incident_id=iid, error=str(e)[:200])

    ledger.append(iid, "GENERATE-REPAIR", "gate", "system",
                  {"verdict": gate["verdict"], "violations": gate["violations"],
                   "policy_version": gate["policy_version"], "ops": ops, "plan_hash": phash,
                   "tier": autonomy_tier, "tier_reasons": tier_reasons})
    ddb.update_incident(iid, plan_ops=json.dumps(ops), plan_hash=phash,
                        plan_rationale=rationale, gate_verdict=gate["verdict"],
                        tier=autonomy_tier, tier_reasons=tier_reasons)
    log("plan_generated", incident_id=iid, ops=len(ops), gate=gate["verdict"], tier=autonomy_tier)
    return {"gate": gate["verdict"], "ops": ops, "plan_hash": phash,
            "rationale": rationale, "tier": autonomy_tier}
