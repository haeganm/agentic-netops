"""Per-incident compliance evidence export (ADR 0015). Maps one incident to the control
assertions an auditor cares about, each backed by concrete ledger/oracle evidence, plus a
cryptographic tamper-evidence check of the ledger itself. Pure read (DDB only) -- no AWS
mutations, no LLM.
"""
import calendar
import json
import time

from shared import ddb, ledger, sts_scope
from shared.log import log


def build_report(incident_id: str) -> dict | None:
    meta = ddb.get_incident(incident_id)
    if not meta:
        return None
    entries = ddb.query_ledger(incident_id)
    by_kind = {}
    for e in entries:
        by_kind.setdefault(e["kind"], []).append(_decode(e))

    chain = ledger.verify_ledger(incident_id)
    gate = _latest(by_kind.get("gate", []))
    # Human decisions only, and only APPROVALS -- a veto/rejection is a decision NOT to
    # authorize, so it must never appear as evidence of authorization.
    decisions = [d for d in by_kind.get("approval", []) if d.get("ledger_actor") == "human"]
    approvals = [d for d in decisions if d.get("decision") == "approved"]
    exec_calls = [t for t in by_kind.get("tool_call", []) if t.get("stage") == "EXECUTE"]

    # least-privilege: recompute the STS session policy the executor would have been scoped to
    session_policy = None
    try:
        ops = json.loads(meta.get("plan_ops") or "[]")
        session_policy = sts_scope.session_policy(ops, json.loads(ddb.get_config("BASELINE")["inventory"]))
    except (KeyError, TypeError, ValueError) as e:
        log("evidence_session_policy_unavailable", incident_id=incident_id, error=str(e)[:200])

    controls = {
        "change_authorized": {
            "tier": meta.get("tier"), "tier_reasons": meta.get("tier_reasons"),
            "approvals": [{"actor": a.get("actor"), "party": a.get("party")} for a in approvals],
            # LOW tier is authorized by policy + an un-exercised veto window, not by a signature
            "authorized_by": "approval" if approvals else "policy (auto-execute, veto window)",
            "other_decisions": [{"actor": d.get("actor"), "decision": d.get("decision")}
                                for d in decisions if d.get("decision") != "approved"],
        },
        "least_privilege": {
            "remediation_via_scoped_sts": session_policy is not None,
            "session_policy": session_policy,
            "applied_operations": [{"action": t.get("action"), "result": t.get("result")} for t in exec_calls],
        },
        "verified": _verified_control(by_kind.get("oracle_verdict", []), meta),
        "human_oversight": {
            "tier": meta.get("tier"), "drift_actor": meta.get("drift_actor"),
            "approvers": [a.get("actor") for a in approvals],
            # SoD is only *exercised* when a human approved; state it, don't assert it
            "sod_enforced": bool(approvals),
            "two_party": len(approvals) >= 2,
        },
        "within_policy": {
            "policy_version": gate.get("policy_version") if gate else None,
            "gate_verdict": gate.get("verdict") if gate else None,
            "violations": gate.get("violations") if gate else None,
        },
        "tamper_evident": chain,
    }
    return {
        "incident_id": incident_id, "status": meta.get("status"),
        "fault_class": meta.get("fault_class"), "created_at": meta.get("created_at"),
        "resolved_at": meta.get("resolved_at"),
        # derived, not stored: nothing wrote mttr_s to the incident, so every export used to
        # print "MTTR: None". Derive it from the two timestamps we already have.
        "mttr_s": mttr_seconds(meta),
        "ledger_entries": len(entries), "controls": controls,
    }


def mttr_seconds(meta: dict) -> int | None:
    """Mean-time-to-repair for one incident: detected -> terminal, in whole seconds."""
    start, end = meta.get("created_at"), meta.get("resolved_at")
    if not start or not end:
        return None
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        return int(calendar.timegm(time.strptime(end[:19] + "Z", fmt))
                   - calendar.timegm(time.strptime(start[:19] + "Z", fmt)))
    except ValueError:
        return None


def _verified_control(oracle: list, meta: dict) -> dict:
    """Each oracle's evidence keyed on WHO attested it (the ledgered actor), not on the shape
    of its payload -- duck-typing on absent keys previously filed probe and CFN-drift verdicts
    under the intent oracle."""
    def by(actor):
        return [o for o in oracle if o.get("ledger_actor") == actor]

    impact = {}
    for o in by("oracle:impact"):
        # a skipped/failed analysis is reported as such, never as "unreachable"
        impact[o.get("stage")] = o.get("reachable") if "reachable" in o else o.get("verdict")

    return {
        "intent": [{"stage": o.get("stage"), "diff_count": o.get("diff_count")} for o in by("oracle:intent")],
        "intent_cfn": [{"stack_drift": o.get("stack_drift")} for o in by("oracle:intent-cfn")],
        "impact_reachable": impact,
        "data_plane": [{"dns": o.get("dns"), "tcp": o.get("tcp")} for o in by("oracle:dataplane")],
        # LIMITED means the RA budget cap skipped an applicable impact check (ADR 0005)
        "verification_scope": meta.get("verification", "full"),
    }


def _decode(entry: dict) -> dict:
    """Ledger entry -> flat dict. The entry's own actor is exposed as `ledger_actor` so a
    payload field named `actor` (approvals carry the operator's email) can't shadow it."""
    try:
        payload = json.loads(entry["payload"])
    except (json.JSONDecodeError, KeyError, TypeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return {**payload, "stage": entry.get("stage"), "ledger_actor": entry.get("actor")}


def _latest(items: list) -> dict | None:
    return items[-1] if items else None
