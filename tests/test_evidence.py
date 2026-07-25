"""Compliance evidence export: all six control assertions present, chain verified."""
import json

from shared import ddb, evidence, ledger


def test_build_report_covers_all_controls(netops_table):
    ddb.put_config("BASELINE", {"inventory": json.dumps({"vpc_id": "vpc-1", "sg_ids": []})})
    ops = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1",
            "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    ddb.create_incident("i1", {"status": "RESOLVED", "fault_class": "dns-disabled",
                               "tier": "LOW", "tier_reasons": ["all additive"],
                               "drift_actor": "arn:aws:iam::1:user/bob",
                               "plan_ops": json.dumps(ops), "gsi1sk": "2026"})
    ledger.append("i1", "GENERATE-REPAIR", "gate", "system",
                  {"verdict": "PASS", "policy_version": "2.0.0", "violations": []})
    ledger.append("i1", "VERIFY", "oracle_verdict", "oracle:intent", {"diff_count": 0})
    ledger.append("i1", "APPROVE", "approval", "human", {"decision": "cancelled", "actor": "op@x.com"})

    r = evidence.build_report("i1")
    c = r["controls"]
    assert set(c) == {"change_authorized", "least_privilege", "verified",
                      "human_oversight", "within_policy", "tamper_evident"}
    assert c["within_policy"]["gate_verdict"] == "PASS"
    assert c["least_privilege"]["session_policy"] is not None  # recomputed scoped policy
    assert c["human_oversight"]["drift_actor"] == "arn:aws:iam::1:user/bob"
    assert c["tamper_evident"]["valid"] is True


def test_report_none_for_missing_incident(netops_table):
    assert evidence.build_report("nope") is None


def _resolved(iid, **extra):
    ddb.put_config("BASELINE", {"inventory": json.dumps({"vpc_id": "vpc-1", "sg_ids": []})})
    ops = [{"action": "modify_vpc_attribute", "resource_id": "vpc-1",
            "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]
    ddb.create_incident(iid, {"status": "RESOLVED", "gsi1sk": "2026", "tier": "LOW",
                              "created_at": "2026-07-24T22:25:08Z",
                              "resolved_at": "2026-07-24T22:26:48Z",
                              "plan_ops": json.dumps(ops), **extra})


def test_each_oracle_is_attributed_to_the_right_control(netops_table):
    """Previously the probe and CFN-drift verdicts were duck-typed into `intent`, so an auditor
    saw the intent oracle firing 3x per incident when it fired once."""
    _resolved("e1")
    ledger.append("e1", "PROVE", "oracle_verdict", "oracle:intent", {"diff_count": 1})
    ledger.append("e1", "MEASURE", "oracle_verdict", "oracle:intent-cfn", {"stack_drift": "DRIFTED"})
    ledger.append("e1", "MEASURE", "oracle_verdict", "oracle:impact", {"reachable": False, "verdict": "succeeded"})
    ledger.append("e1", "MEASURE", "oracle_verdict", "oracle:dataplane", {"dns": "pass", "tcp": "pass"})
    ledger.append("e1", "VERIFY", "oracle_verdict", "oracle:impact", {"reachable": True, "verdict": "succeeded"})

    v = evidence.build_report("e1")["controls"]["verified"]
    assert len(v["intent"]) == 1                  # exactly one, not polluted
    assert len(v["intent_cfn"]) == 1
    assert len(v["data_plane"]) == 1
    # the before/after reachability flip is the headline proof
    assert v["impact_reachable"] == {"MEASURE": False, "VERIFY": True}


def test_a_veto_is_not_counted_as_an_approval(netops_table):
    """A CANCELLED incident never executed. Reporting the vetoing operator under
    change_authorized.approvals would claim authorization that never happened."""
    _resolved("e2", status="CANCELLED")
    ledger.append("e2", "APPROVE", "approval", "human", {"decision": "cancelled", "actor": "op@x.com"})
    c = evidence.build_report("e2")["controls"]
    assert c["change_authorized"]["approvals"] == []
    assert c["change_authorized"]["other_decisions"] == [{"actor": "op@x.com", "decision": "cancelled"}]
    assert c["human_oversight"]["approvers"] == []
    assert c["human_oversight"]["sod_enforced"] is False   # no approval => SoD never evaluated


def test_two_party_approvals_are_both_reported(netops_table):
    _resolved("e3", tier="HIGH", first_approver="a@x.com")
    ledger.append("e3", "APPROVE", "approval", "human",
                  {"decision": "approved", "actor": "a@x.com", "party": "first"})
    ledger.append("e3", "APPROVE", "approval", "human",
                  {"decision": "approved", "actor": "b@x.com", "party": "second"})
    c = evidence.build_report("e3")["controls"]
    assert [a["actor"] for a in c["change_authorized"]["approvals"]] == ["a@x.com", "b@x.com"]
    assert c["human_oversight"]["two_party"] is True


def test_mttr_is_derived_not_stored(netops_table):
    """Nothing wrote mttr_s to the incident, so the compliance export used to print None."""
    _resolved("e4")
    assert evidence.build_report("e4")["mttr_s"] == 100  # 22:26:48 - 22:25:08


def test_broken_chain_surfaces_in_the_report(netops_table):
    from conftest import ledger_sk
    _resolved("e5")
    ledger.append("e5", "DETECT", "event", "system", {"a": 1})
    ledger.append("e5", "EXECUTE", "tool_call", "system", {"a": 2})
    ddb.table().update_item(Key={"pk": "INCIDENT#e5", "sk": ledger_sk("e5", 2)},
                            UpdateExpression="SET payload = :p",
                            ExpressionAttributeValues={":p": '{"a": 999}'})
    assert evidence.build_report("e5")["controls"]["tamper_evident"]["valid"] is False


def test_missing_plan_ops_degrades_the_least_privilege_claim(netops_table):
    """If the session policy can't be recomputed, the control must say so -- not assert True."""
    ddb.put_config("BASELINE", {"inventory": json.dumps({"vpc_id": "vpc-1"})})
    ddb.create_incident("e6", {"status": "FAILED", "gsi1sk": "2026"})   # no plan_ops
    lp = evidence.build_report("e6")["controls"]["least_privilege"]
    assert lp["session_policy"] == {"Version": "2012-10-17",
                                    "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*",
                                                   "Resource": "*"}]}
    assert lp["applied_operations"] == []
