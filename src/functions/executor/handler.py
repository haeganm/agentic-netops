"""EXECUTE: apply the approved plan with per-incident scoped STS credentials.
Re-checks the plan hash against what was approved AND independently re-runs the policy
gate against a freshly-read baseline (defense-in-depth at the one place holding real
credentials), resolves runtime association ids read-only, applies ops sequentially, and
ledgers every op result.
"""

import json

from shared import baseline as base_mod
from shared import ddb, ledger, policy, sts_scope
from shared import plan as plan_mod
from shared.log import log


def lambda_handler(event, context):
    iid = event["incident_id"]
    ops = event["ops"]

    meta = ddb.get_incident(iid) or {}
    approved_hash = meta.get("plan_hash")
    if plan_mod.plan_hash(ops) != approved_hash:
        raise ValueError(f"plan hash mismatch: approved={approved_hash}")

    cfg = ddb.get_config("BASELINE")
    base = json.loads(cfg["snapshot"])
    inventory = json.loads(cfg["inventory"])
    # re-run the gate here, freshly, right before privileged action. The diff is
    # re-derived from live-vs-baseline so a plan that no longer converges is rejected.
    diff = base_mod.diff(base, base_mod.snapshot(inventory))
    gate = policy.evaluate(ops, diff, base, inventory)
    if gate["verdict"] != "PASS":
        ledger.append(iid, "EXECUTE", "gate", "system",
                      {"verdict": "FAIL", "violations": gate["violations"], "stage": "pre-execute"})
        raise ValueError(f"executor gate re-check failed: {gate['violations']}")

    ec2 = sts_scope.scoped_ec2_client(iid, ops, inventory)
    applied = []
    for op in ops:
        action, params = op["action"], dict(op["params"])
        # _resolve and the mutation share one try so a mid-loop failure of EITHER is ledgered
        # with applied_so_far; the "ok" append sits OUTSIDE it so a successful mutation is
        # never re-recorded as an error if only the ledger write fails.
        try:
            action, params = _resolve(ec2, op)
            getattr(ec2, action)(**params)
        except Exception as e:
            ledger.append(iid, "EXECUTE", "tool_call", "system",
                          {"action": action, "params": params,
                           "result": "error", "error": str(e)[:500], "applied_so_far": applied})
            raise
        applied.append(action)
        ledger.append(iid, "EXECUTE", "tool_call", "system",
                      {"action": action, "params": params, "result": "ok"})
    log("executed", incident_id=iid, ops=len(applied))
    return {"applied": applied}


def _resolve(ec2, op: dict) -> tuple[str, dict]:
    """Swap logical params for the runtime association ids the revert APIs require, returning
    (action, params) -- the action can change: a subnet that was plainly DISASSOCIATED has no
    explicit association to replace (only the implicit main-table fallback, which the
    association.subnet-id filter does not report), so the converge call is associate, not
    replace. Fails fast (before any mutation) if a NACL association can't be resolved, rather
    than issuing a malformed call mid-loop."""
    action, params = op["action"], dict(op["params"])
    if action == "replace_route_table_association":
        subnet = params.pop("SubnetId")
        rts = ec2.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet]}])["RouteTables"]
        assoc = _find_assoc(rts, subnet, "RouteTableAssociationId")
        if assoc:
            params["AssociationId"] = assoc
        else:
            action = "associate_route_table"
            params["SubnetId"] = subnet
    elif action == "replace_network_acl_association":
        subnet = params.pop("SubnetId")
        nacls = ec2.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet]}])["NetworkAcls"]
        assoc = _find_assoc(nacls, subnet, "NetworkAclAssociationId")
        if not assoc:
            # unlike route tables, a subnet always has a live NACL association to replace
            raise ValueError(f"no association for subnet {subnet} (cannot resolve NetworkAclAssociationId)")
        params["AssociationId"] = assoc
    return action, params


def _find_assoc(resources: list, subnet: str, id_field: str) -> str | None:
    for r in resources:
        for a in r.get("Associations", []):
            if a.get("SubnetId") == subnet:
                return a[id_field]
    return None
