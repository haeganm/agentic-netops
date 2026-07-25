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
    ledger.append("iA", "DETECT", "event", "system", {"x": 1})
    resp = json.loads(handler.lambda_handler(_req("GET /incidents/{id}/verify", "iA"), None)["body"])
    assert resp["valid"] is True and resp["length"] == 1
