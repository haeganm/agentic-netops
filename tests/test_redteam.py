"""Standing adversarial red-team suite (ADR: SECURITY.md A1-A8). Each test is an ATTACK that
MUST be blocked, run at moto/unit level (credential-free, $0 -- never touches live RA/Bedrock).
This is security testing as a permanent, measurable artifact, not a one-time audit."""
import json

import boto3
from conftest import FakeSfn, ledger_sk

from functions.api import handler as api
from functions.detector import handler as detector
from functions.planner import handler as planner
from shared import ddb, ledger, plan, policy, tier

BASE = {
    "sgs": {"sg-1": {"ingress": [json.dumps({"cidr": "10.42.0.0/24", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)], "egress": []}},
    "route_tables": {}, "nacls": {}, "vpc": {"vpc-1": {"dns_support": True, "dns_hostnames": True}}, "enis": {},
}
INV = {"vpc_id": "vpc-1", "sg_ids": ["sg-1"], "rt_ids": [], "nacl_id": "acl-1",
       "subnet_ids": [], "eni_ids": [], "igw_id": "igw-1"}



def _cloudtrail(event_name, resource, actor="arn:aws:iam::1:user/x", event_id="e1"):
    detail = {"eventName": event_name, "eventID": event_id, "eventTime": "2026-07-24T00:00:00Z",
              "userIdentity": {"arn": actor}, "requestParameters": {"groupId": resource}}
    return {"Records": [{"messageId": "m", "body": json.dumps({"detail": detail})}]}


# --- ATTACKS -------------------------------------------------------------------------------

def test_A_malicious_cloudtrail_payload_ignored(netops_table):
    ddb.put_config("BASELINE", {"inventory": json.dumps({"sg_ids": ["sg-1"], "vpc_id": "vpc-1"})})
    ddb.put_config("MODE", {"mode": "normal"})
    # junk event referencing a NON-lab resource -> no incident
    detector.lambda_handler(_cloudtrail("RevokeSecurityGroupIngress", "sg-EVIL; DROP"), None)
    assert ddb.list_incidents() == []


def test_B_drift_forced_to_lower_tier_still_escalates(netops_table):
    # additive noise can't hide a revoke: any removing op keeps it >= MEDIUM (fail-closed)
    ops = [{"action": "authorize_security_group_ingress", "resource_id": "sg-1", "params": {}},
           {"action": "revoke_security_group_egress", "resource_id": "sg-1", "params": {}}]
    t, _ = tier.decide("sg-egress-removed", ops, [{"section": "sgs", "resource_id": "sg-1", "field": "egress"}], [{"verdict": "ok"}])
    assert t in (tier.MEDIUM, tier.HIGH)  # never LOW with a revoke present
    # and a world-open INGRESS is always HIGH
    diff = [{"kind": "extra", "section": "sgs", "resource_id": "sg-1", "field": "ingress",
             "expected": None, "actual": json.dumps({"cidr": "0.0.0.0/0"})}]
    t2, _ = tier.decide("sg-open-world", [{"action": "revoke_security_group_ingress", "params": {}}], diff, [{"verdict": "ok"}])
    assert t2 == tier.HIGH


def test_C_plan_tampering_blocked_at_approval(netops_table):
    good = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1", "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    ddb.create_incident("i", {"status": "AWAITING_APPROVAL", "task_token": "T", "gsi1sk": "1",
                              "plan_hash": plan.plan_hash(good), "plan_ops": json.dumps([{"action": "delete_route", "resource_id": "x", "params": {}}])})
    r = api.lambda_handler({"routeKey": "POST /incidents/{id}/approve", "pathParameters": {"id": "i"},
                            "requestContext": {"authorizer": {"jwt": {"claims": {"email": "a@x"}}}}}, None)
    assert r["statusCode"] == 409 and "integrity" in json.loads(r["body"])["error"]


def test_C2_params_only_tampering_blocked_at_approval(netops_table):
    """Same ACTIONS, different PARAMS: a plan_hash weakened to cover only action names would
    pass test_C above while letting test_G's exact payload (EnableDnsSupport True->False)
    through the approve-time integrity check. The hash must be params-sensitive."""
    good = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1", "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    tampered = json.loads(json.dumps(good))
    tampered[0]["params"]["EnableDnsSupport"]["Value"] = False
    ddb.create_incident("i", {"status": "AWAITING_APPROVAL", "task_token": "T", "gsi1sk": "1",
                              "plan_hash": plan.plan_hash(good), "plan_ops": json.dumps(tampered)})
    r = api.lambda_handler({"routeKey": "POST /incidents/{id}/approve", "pathParameters": {"id": "i"},
                            "requestContext": {"authorizer": {"jwt": {"claims": {"email": "a@x"}}}}}, None)
    assert r["statusCode"] == 409 and "integrity" in json.loads(r["body"])["error"]


def test_D_replayed_approval_after_resolve_is_409(netops_table):
    ddb.create_incident("i", {"status": "RESOLVED", "gsi1sk": "1"})  # no token, terminal
    r = api.lambda_handler({"routeKey": "POST /incidents/{id}/approve", "pathParameters": {"id": "i"},
                            "requestContext": {"authorizer": {"jwt": {"claims": {"email": "a@x"}}}}}, None)
    assert r["statusCode"] == 409


def test_E_two_party_same_user_blocked(netops_table, monkeypatch):
    calls = {}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSfn(calls))
    good = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1", "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    ddb.create_incident("i", {"status": "AWAITING_SECOND_APPROVAL", "task_token": "T", "gsi1sk": "1",
                              "plan_hash": plan.plan_hash(good), "plan_ops": json.dumps(good), "first_approver": "a@x"})
    r = api.lambda_handler({"routeKey": "POST /incidents/{id}/approve", "pathParameters": {"id": "i"},
                            "requestContext": {"authorizer": {"jwt": {"claims": {"email": "a@x"}}}}}, None)
    assert r["statusCode"] == 403
    # the block must happen BEFORE the token send -- a 403 that still resumed the workflow
    # would be the two-party bypass this test exists to prevent
    assert "success" not in calls, "403 returned but the task token was completed anyway"


def test_F_ledger_tamper_detected(netops_table):
    ledger.append("i", "DETECT", "event", "system", {"a": 1})
    ledger.append("i", "EXECUTE", "tool_call", "system", {"a": 2})
    ddb.table().update_item(Key={"pk": "INCIDENT#i", "sk": ledger_sk("i", 2)},
                            UpdateExpression="SET actor = :a", ExpressionAttributeValues={":a": "attacker"})
    assert ledger.verify_ledger("i")["valid"] is False


def test_G_low_weaponization_fails_gate(netops_table):
    # an attacker-crafted "restore" that targets a NON-baseline value never reaches LOW: the
    # gate rejects it first (converge-only), so no auto-exec of a hostile plan is possible.
    diff = [{"kind": "changed", "section": "vpc", "resource_id": "vpc-1", "field": "dns_support", "expected": True, "actual": False}]
    evil = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1", "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": False}}}]
    assert policy.evaluate(evil, diff, BASE, INV)["verdict"] == "FAIL"


def _seed_low_tier_incident(iid="k1", seed_probe=True):
    """A dns-disabled drift: single resource, one additive op, clean oracles -> LOW.
    dns-disabled expects a data-plane probe verdict (ORACLE_POLICY), so a healthy run has one
    in the ledger by planner time -- seed it, or the missing-evidence rule escalates."""
    ddb.put_config("BASELINE", {"snapshot": json.dumps(BASE), "inventory": json.dumps(INV)})
    ddb.create_incident(iid, {"status": "PROVING", "gsi1sk": "2026"})
    if seed_probe:
        ledger.append(iid, "MEASURE", "oracle_verdict", "oracle:dataplane",
                      {"dns": "pass", "tcp": "pass", "latency_ms": 8})
    diff = [{"kind": "changed", "section": "vpc", "resource_id": "vpc-1",
             "field": "dns_support", "expected": True, "actual": False}]
    return {"incident_id": iid, "diff": diff, "diagnosis": {}}


def test_H_kill_switch_forces_human(netops_table):
    """Runs the REAL planner. The previous version of this test re-implemented the kill-switch
    rule inside the test body, so it stayed green even if the feature were deleted -- worse than
    no test, for the one control that disables all no-human execution."""
    event = _seed_low_tier_incident("k1")
    # baseline: no kill-switch -> this drift is genuinely LOW (auto-executes)
    assert planner.lambda_handler(event, None)["tier"] == tier.LOW

    # engage the kill-switch: the SAME input must now demand a human
    ddb.put_config("AUTONOMY", {"mode": "manual"})
    out = planner.lambda_handler(_seed_low_tier_incident("k2"), None)
    assert out["tier"] == tier.MEDIUM
    reasons = ddb.get_incident("k2")["tier_reasons"]
    assert any("kill-switch" in r for r in reasons), reasons


def test_J_crashed_oracle_cannot_pass_as_clean(netops_table):
    """ATTACK: suppress an oracle (throttle its API, revoke its IAM) so it CRASHES instead of
    returning a bad verdict. The ASL catches the failure and flows on; nothing is ledgered, and
    'no verdicts' used to read as 'oracles clean' -> LOW auto-exec with no human. The planner
    must treat expected-but-absent oracle evidence as an escalation."""
    event = _seed_low_tier_incident("k4", seed_probe=False)  # probe expected, never ledgered
    out = planner.lambda_handler(event, None)
    assert out["tier"] == tier.HIGH
    reasons = ddb.get_incident("k4")["tier_reasons"]
    assert any("oracle" in r for r in reasons), reasons


def test_I_planner_survives_a_truncated_ledger_payload(netops_table):
    """A wide drift makes PROVE's ledger payload exceed the clamp; an unguarded json.loads on
    the sliced string used to fail the planner -- i.e. the loop broke on the WIDEST drift."""
    event = _seed_low_tier_incident("k3")
    ledger.append("k3", "PROVE", "oracle_verdict", "oracle:intent", {"blob": "x" * 20000})
    assert any(e["truncated"] for e in ddb.query_ledger("k3")), "fixture did not truncate"
    out = planner.lambda_handler(event, None)  # must not raise JSONDecodeError
    assert out["tier"] in (tier.LOW, tier.MEDIUM, tier.HIGH)



