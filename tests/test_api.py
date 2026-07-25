"""Console API: the human-in-the-loop authorization boundary. Token stripping,
approval guards, plan-integrity binding, 409 paths."""
import json

import boto3
from conftest import FakeSfn

from functions.api import handler
from shared import ddb, ledger, plan


def _req(route, iid=None, body=None, actor="op@x.com"):
    ev = {"routeKey": route, "requestContext": {"authorizer": {"jwt": {"claims": {"email": actor}}}}}
    if iid:
        ev["pathParameters"] = {"id": iid}
    if body:
        ev["body"] = json.dumps(body)
    return ev


def test_task_token_stripped_from_list_and_detail(netops_table):
    ddb.create_incident("i1", {"status": "AWAITING_APPROVAL", "gsi1sk": "2026",
                               "task_token": "SECRET", "plan_ops": "[]",
                               "plan_hash": plan.plan_hash([])})
    listed = json.loads(handler.lambda_handler(_req("GET /incidents"), None)["body"])
    assert all("task_token" not in i for i in listed)
    detail = json.loads(handler.lambda_handler(_req("GET /incidents/{id}", "i1"), None)["body"])
    assert "task_token" not in detail["meta"]


def test_approve_on_non_awaiting_is_409(netops_table):
    ddb.create_incident("i2", {"status": "PROVING", "gsi1sk": "2026"})
    resp = handler.lambda_handler(_req("POST /incidents/{id}/approve", "i2"), None)
    assert resp["statusCode"] == 409


def test_approve_rejects_tampered_plan_ops(netops_table):
    good = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1",
             "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    # META stores the hash of the GOOD plan, but plan_ops was swapped to something else
    ddb.create_incident("i3", {"status": "AWAITING_APPROVAL", "gsi1sk": "2026",
                               "task_token": "T", "plan_hash": plan.plan_hash(good),
                               "plan_ops": json.dumps([{"action": "delete_route", "resource_id": "x", "params": {}}])})
    resp = handler.lambda_handler(_req("POST /incidents/{id}/approve", "i3"), None)
    assert resp["statusCode"] == 409
    assert "integrity" in json.loads(resp["body"])["error"]


def test_approve_happy_path_sends_task_success(netops_table, monkeypatch):
    good = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1",
             "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    ddb.create_incident("i4", {"status": "AWAITING_APPROVAL", "gsi1sk": "2026",
                               "task_token": "TOKEN123", "plan_hash": plan.plan_hash(good),
                               "plan_ops": json.dumps(good)})
    calls = {}
    monkeypatch.setattr(boto3, "client", lambda svc, *a, **k: FakeSfn(calls))
    resp = handler.lambda_handler(_req("POST /incidents/{id}/approve", "i4"), None)
    assert resp["statusCode"] == 200
    assert calls["success"] == "TOKEN123"




def test_limits_route(netops_table):
    ddb.put_ra_budget(used=5, cap=30)
    resp = json.loads(handler.lambda_handler(_req("GET /limits"), None)["body"])
    assert resp == {"ra_used": 5, "ra_cap": 30}


_GOOD = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1",
          "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]


def _awaiting(iid, status="AWAITING_APPROVAL", **extra):
    ddb.create_incident(iid, {"status": status, "gsi1sk": "2026", "task_token": "T",
                              "plan_hash": plan.plan_hash(_GOOD), "plan_ops": json.dumps(_GOOD), **extra})


def test_sod_blocks_approver_who_caused_drift(netops_table, monkeypatch):
    ddb.put_config("APPROVERS", {"map": {"op@x.com": "arn:aws:iam::1:user/op"}})
    _awaiting("i5", drift_actor="arn:aws:iam::1:user/op")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn({}))
    resp = handler.lambda_handler(_req("POST /incidents/{id}/approve", "i5"), None)
    assert resp["statusCode"] == 403 and "segregation" in json.loads(resp["body"])["error"]


def test_two_party_blocks_same_user_twice(netops_table, monkeypatch):
    _awaiting("i6", status="AWAITING_SECOND_APPROVAL", first_approver="op@x.com")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn({}))
    same = handler.lambda_handler(_req("POST /incidents/{id}/approve", "i6", actor="op@x.com"), None)
    assert same["statusCode"] == 403 and "two-party" in json.loads(same["body"])["error"]


def test_two_party_allows_distinct_second_approver(netops_table, monkeypatch):
    _awaiting("i7", status="AWAITING_SECOND_APPROVAL", first_approver="op@x.com")
    calls = {}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn(calls))
    ok = handler.lambda_handler(_req("POST /incidents/{id}/approve", "i7", actor="other@x.com"), None)
    assert ok["statusCode"] == 200 and calls["success"] == "T"


def test_cancel_vetoes_auto_exec(netops_table, monkeypatch):
    _awaiting("i8", status="AUTO_EXEC_PENDING")
    calls = {}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn(calls))
    resp = handler.lambda_handler(_req("POST /incidents/{id}/cancel", "i8"), None)
    assert resp["statusCode"] == 200 and calls["failure"] == "T"


def test_cancel_on_non_pending_is_409(netops_table):
    _awaiting("i9", status="AWAITING_APPROVAL")
    resp = handler.lambda_handler(_req("POST /incidents/{id}/cancel", "i9"), None)
    assert resp["statusCode"] == 409


def test_verify_route(netops_table):
    # the incident must exist: verify now 404s on an unknown id, and a ledger without a META
    # item was never a reachable state anyway
    ddb.create_incident("iA", {"status": "RESOLVED", "gsi1sk": "2026"})
    ledger.append("iA", "DETECT", "event", "system", {"x": 1})
    resp = json.loads(handler.lambda_handler(_req("GET /incidents/{id}/verify", "iA"), None)["body"])
    assert resp["valid"] is True and resp["length"] == 1


def test_verify_on_unknown_incident_is_404_not_a_tamper_report(netops_table):
    """REGRESSION: verify used to return 200 {valid: false, first_break_seq: 1} for an id that
    simply does not exist -- a typo was indistinguishable from real tampering in the one tool
    whose whole job is telling those apart."""
    resp = handler.lambda_handler(_req("GET /incidents/{id}/verify", "does-not-exist"), None)
    assert resp["statusCode"] == 404


# --- SoD is recusal, not just "cannot approve" (ADR 0016) ------------------------------------
# The causer previously kept the ability to REJECT or VETO the repair for their own drift. When
# the drift IS the security hole, blocking the fix preserves it.

def _causer_setup(iid, status="AWAITING_APPROVAL"):
    ddb.put_config("APPROVERS", {"map": {"causer@x.com": "arn:aws:iam::1:user/op"}})
    _awaiting(iid, status=status, drift_actor="arn:aws:iam::1:user/op")


def test_sod_blocks_reject_by_the_drift_causer(netops_table, monkeypatch):
    _causer_setup("iS1")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn({}))
    resp = handler.lambda_handler(
        _req("POST /incidents/{id}/reject", "iS1", actor="causer@x.com"), None)
    assert resp["statusCode"] == 403 and "segregation" in json.loads(resp["body"])["error"]


def test_sod_blocks_veto_by_the_drift_causer(netops_table, monkeypatch):
    _causer_setup("iS2", status="AUTO_EXEC_PENDING")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn({}))
    resp = handler.lambda_handler(
        _req("POST /incidents/{id}/cancel", "iS2", actor="causer@x.com"), None)
    assert resp["statusCode"] == 403 and "segregation" in json.loads(resp["body"])["error"]


def test_recusal_does_not_block_a_different_operator(netops_table, monkeypatch):
    """The fix must not break the legitimate path: anyone who did NOT cause the drift may
    still reject and veto."""
    _causer_setup("iS3")
    _causer_setup("iS4", status="AUTO_EXEC_PENDING")
    calls = {}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn(calls))
    rej = handler.lambda_handler(_req("POST /incidents/{id}/reject", "iS3", actor="other@x.com"), None)
    assert rej["statusCode"] == 200
    can = handler.lambda_handler(_req("POST /incidents/{id}/cancel", "iS4", actor="other@x.com"), None)
    assert can["statusCode"] == 200


# --- identity must be attributable ------------------------------------------------------------

def _no_claims(route, iid):
    """A token that carried no email claim: actor used to default to the string "unknown"."""
    return {"routeKey": route, "pathParameters": {"id": iid},
            "requestContext": {"authorizer": {"jwt": {"claims": {}}}}}


def test_unattributable_caller_cannot_decide(netops_table, monkeypatch):
    _awaiting("iU1")
    _awaiting("iU2", status="AUTO_EXEC_PENDING")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn({}))
    for route, iid in (("POST /incidents/{id}/approve", "iU1"),
                       ("POST /incidents/{id}/reject", "iU1"),
                       ("POST /incidents/{id}/cancel", "iU2")):
        resp = handler.lambda_handler(_no_claims(route, iid), None)
        assert resp["statusCode"] == 403, route
        assert "unattributable" in json.loads(resp["body"])["error"]


def test_unattributable_caller_may_still_read(netops_table):
    """Reads are not state-changing; only POST routes require attribution."""
    ddb.create_incident("iU3", {"status": "RESOLVED", "gsi1sk": "2026"})
    ev = {"routeKey": "GET /incidents", "requestContext": {"authorizer": {"jwt": {"claims": {}}}}}
    assert handler.lambda_handler(ev, None)["statusCode"] == 200


def test_decisions_on_unknown_incident_are_409(netops_table, monkeypatch):
    """Locks in non-enumerating behaviour: missing and wrong-state are indistinguishable."""
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn({}))
    for route in ("POST /incidents/{id}/approve", "POST /incidents/{id}/reject",
                  "POST /incidents/{id}/cancel"):
        resp = handler.lambda_handler(_req(route, "nope"), None)
        assert resp["statusCode"] == 409, route


def test_first_approver_slot_is_takeable_exactly_once(netops_table):
    """Direct test of the A8 race fix, which had none: the conditional write must reject a
    second claim rather than overwrite the first approver."""
    _awaiting("iF1")
    assert ddb.claim_first_approver("iF1", "first@x.com") is True
    assert ddb.claim_first_approver("iF1", "second@x.com") is False
    assert ddb.get_incident("iF1")["first_approver"] == "first@x.com"
