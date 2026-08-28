"""Console API (Cognito-JWT-authorized at the gateway). Approve/Reject complete the
Step Functions task token stored on the incident; everything else is read-only."""
import contextlib
import json

from shared import ddb, evidence, ledger, plan, status
from shared.log import log


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    path_params = event.get("pathParameters") or {}
    claims = (event.get("requestContext", {}).get("authorizer", {})
              .get("jwt", {}).get("claims", {}))
    actor = claims.get("email")

    try:
        # fail closed on attribution: every POST ledgers `actor` as who authorised a network
        # change, so a token with no email claim is refused. By prefix, so future POST routes
        # inherit the guard (SECURITY.md pass 4).
        if route.startswith("POST /") and not actor:
            log("unattributable_caller", route=route)
            return _err(403, "unattributable caller: token carries no email claim")

        if route == "GET /incidents":
            items = [_public(i) for i in ddb.list_incidents()]
            return _ok(items)

        if route == "GET /incidents/{id}":
            iid = path_params["id"]
            meta = ddb.get_incident(iid)
            if not meta:
                return _err(404, "not found")
            return _ok({"meta": _public(meta), "ledger": ddb.query_ledger(iid)})

        if route == "POST /incidents/{id}/approve":
            return _decide(path_params["id"], actor, approve=True, body=event.get("body"))

        if route == "POST /incidents/{id}/reject":
            return _decide(path_params["id"], actor, approve=False, body=event.get("body"))

        if route == "POST /incidents/{id}/cancel":
            return _cancel(path_params["id"], actor)

        if route == "GET /incidents/{id}/verify":
            # 404 on an unknown id: an empty chain must never read as tampering
            iid = path_params["id"]
            if not ddb.get_incident(iid):
                return _err(404, "not found")
            return _ok(ledger.verify_ledger(iid))

        if route == "GET /incidents/{id}/evidence":
            report = evidence.build_report(path_params["id"])
            return _err(404, "not found") if report is None else _ok(report)

        if route == "GET /evals":
            return _ok(ddb.list_evals())

        if route == "GET /limits":
            ra = ddb.get_ra_budget() or {}
            return _ok({"ra_used": int(ra.get("used", 0)), "ra_cap": int(ra.get("cap", 0))})

        return _err(404, f"unknown route {route}")
    except Exception as e:  # noqa: BLE001
        log("api_error", route=route, error=str(e)[:300])
        return _err(500, "internal error")


def _maps_to_drift(actor: str, meta: dict) -> bool:
    """Segregation of duties (ADR 0013/0016): is this operator the one who caused the drift?
    Resolves the Cognito-email -> IAM-ARN mismatch via CONFIG#APPROVERS.

    Applies to EVERY decision, not just approval -- see _recused."""
    approvers = (ddb.get_config("APPROVERS") or {}).get("map", {})
    return approvers.get(actor) is not None and approvers.get(actor) == meta.get("drift_actor")


def _recused(actor: str, meta: dict, verb: str):
    """403 if the drift-causer is trying to decide the fate of their own change (ADR 0016).

    SoD originally guarded approval only, which left the causer able to REJECT or VETO the
    repair for drift they themselves caused. That is not a safe asymmetry: when the drift IS
    the security hole (say a world-open SG rule), blocking the fix preserves the hole, and the
    ledger records it as an ordinary operator decision. Segregation of duties means recusal
    from the decision, not merely from approving it.

    Recusal costs nothing operationally: on MEDIUM/HIGH the incident then expires with the
    network still drifted -- exactly what a reject would have achieved -- and on LOW the repair
    proceeds, which is strictly better."""
    if _maps_to_drift(actor, meta):
        log("sod_recusal", actor=actor, verb=verb)
        return _err(403, f"segregation of duties: you caused this change, so you may not "
                         f"{verb} its remediation -- another operator must decide")
    return None


def _decide(iid: str, actor: str, approve: bool, body):
    import boto3

    meta = ddb.get_incident(iid)
    if not meta or meta.get("status") not in (status.AWAITING_APPROVAL, status.AWAITING_SECOND_APPROVAL) or not meta.get("task_token"):
        return _err(409, "incident is not awaiting approval")
    second = meta.get("status") == status.AWAITING_SECOND_APPROVAL

    # SoD applies to BOTH verbs: the causer is recused from the decision entirely (ADR 0016).
    if recused := _recused(actor, meta, "approve" if approve else "reject"):
        return recused

    if approve:
        # plan integrity: the stored plan_ops must still hash to the approved plan_hash.
        # Approve-only by nature: a reject consents to nothing, so there is no plan to bind.
        shown = json.loads(meta.get("plan_ops") or "[]")
        if plan.plan_hash(shown) != meta.get("plan_hash"):
            log("plan_integrity_fail", incident_id=iid)
            return _err(409, "plan integrity check failed")
        # The second approver must be DISTINCT from the first (two-party control). Also
        # approve-only: a rejection has no second party to be distinct from.
        if second and actor == meta.get("first_approver"):
            return _err(403, "two-party control: a second, distinct approver is required")

    # CLAIM the first-approver slot atomically BEFORE sending the token. A conditional write
    # means the slot can be taken exactly once: without it, a second click landing in the
    # (seconds-wide) gap before AWAITING_SECOND_APPROVAL could overwrite first_approver and
    # let one human satisfy both parties of a two-party control.
    if approve and not second and not ddb.claim_first_approver(iid, actor):
        return _err(409, "first approval already recorded for this incident")

    sfn = boto3.client("stepfunctions")
    reason = ""
    if body:
        with contextlib.suppress(json.JSONDecodeError):
            reason = str(json.loads(body).get("reason", ""))[:500]
    try:
        if approve:
            sfn.send_task_success(taskToken=meta["task_token"],
                                  output=json.dumps({"approved_by": actor}))
        else:
            sfn.send_task_failure(taskToken=meta["task_token"], error="Rejected",
                                  cause=reason or f"rejected by {actor}")
    except (sfn.exceptions.TaskTimedOut, sfn.exceptions.TaskDoesNotExist,
            sfn.exceptions.InvalidToken):
        # the wait already resolved (timeout, or another operator won the race)
        return _err(409, "approval window already closed")

    # post-commit: the workflow is already proceeding, so a ledger failure must not turn a
    # successful approval into a 500 (it would leave an execution with no recorded approver).
    try:
        ledger.append(iid, "APPROVE", "approval", "human",
                      {"decision": "approved" if approve else "rejected", "actor": actor,
                       "reason": reason, "party": "second" if second else "first"})
    except Exception as e:  # noqa: BLE001 - post-commit, log and continue
        log("ledger_append_failed", incident_id=iid, stage="APPROVE", error=str(e)[:300])
    log("decision", incident_id=iid, approved=approve, actor=actor, second=second)
    return _ok({"decision": "approved" if approve else "rejected"})


def _cancel(iid: str, actor: str):
    """Veto a LOW-tier auto-execution during its window (ADR 0012)."""
    import boto3

    meta = ddb.get_incident(iid)
    if not meta or meta.get("status") != status.AUTO_EXEC_PENDING or not meta.get("task_token"):
        return _err(409, "incident is not in an auto-execute veto window")
    # A veto is a decision too: without this, whoever caused the drift could cancel the
    # self-heal of their own change and the outage would persist behind an ordinary-looking
    # veto (ADR 0016).
    if recused := _recused(actor, meta, "veto"):
        return recused
    sfn = boto3.client("stepfunctions")
    try:
        sfn.send_task_failure(taskToken=meta["task_token"], error="Cancelled",
                              cause=f"vetoed by {actor}")
    except (sfn.exceptions.TaskTimedOut, sfn.exceptions.TaskDoesNotExist,
            sfn.exceptions.InvalidToken):
        # same three-way catch as _decide: the window may have closed under us
        return _err(409, "veto window already closed")
    ledger.append(iid, "APPROVE", "approval", "human", {"decision": "cancelled", "actor": actor})
    log("cancelled", incident_id=iid, actor=actor)
    return _ok({"decision": "cancelled"})


def _public(item: dict) -> dict:
    return {k: v for k, v in item.items() if k != "task_token"}


def _ok(data):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps(data, default=str)}


def _err(code: int, msg: str):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": msg})}
