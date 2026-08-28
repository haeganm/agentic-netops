"""classify -> plan -> policy: the deterministic spine of the loop, per fault class."""
import json

from shared import classify, plan, policy

INVENTORY = {"vpc_id": "vpc-1", "sg_ids": ["sg-1", "sg-2"], "rt_ids": ["rtb-1"],
             "nacl_id": "acl-1", "subnet_ids": ["subnet-1"], "eni_ids": ["eni-1"],
             "igw_id": "igw-1"}

BASELINE = {
    "sgs": {"sg-1": {"ingress": [json.dumps({"cidr": "10.42.0.0/24", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)],
                     "egress": []}},
    "route_tables": {"rtb-1": {"routes": [json.dumps({"dest": "0.0.0.0/0", "state": "active", "target": "igw-1"}, sort_keys=True)],
                               "subnets": ["subnet-1"]}},
    "nacls": {"acl-1": {"entries": [], "subnets": ["subnet-1"]}},
    "vpc": {"vpc-1": {"dns_support": True, "dns_hostnames": True}},
    "enis": {"eni-1": {"sgs": ["sg-1"]}},
}


def _e(kind, section, rid, field, expected=None, actual=None):
    return {"kind": kind, "section": section, "resource_id": rid, "field": field,
            "expected": expected, "actual": actual}


def test_sg_ingress_removed_end_to_end():
    rule = BASELINE["sgs"]["sg-1"]["ingress"][0]
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected=rule)]
    assert classify.classify(diff) == "sg-ingress-removed"
    ops = plan.build(diff, BASELINE)
    assert ops == [{"action": "authorize_security_group_ingress", "resource_id": "sg-1",
                    "params": {"GroupId": "sg-1", "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                         "IpRanges": [{"CidrIp": "10.42.0.0/24"}]}]}}]
    assert policy.evaluate(ops, diff, BASELINE, INVENTORY)["verdict"] == "PASS"


def test_sg_open_world_classified_and_reverted():
    bad = json.dumps({"cidr": "0.0.0.0/0", "from": 22, "proto": "tcp", "to": 22}, sort_keys=True)
    diff = [_e("extra", "sgs", "sg-1", "ingress", actual=bad)]
    assert classify.classify(diff) == "sg-open-world"
    ops = plan.build(diff, BASELINE)
    assert ops[0]["action"] == "revoke_security_group_ingress"
    assert policy.evaluate(ops, diff, BASELINE, INVENTORY)["verdict"] == "PASS"


def test_ipv6_world_open_classified_open_world():
    """::/0 is exactly as world-open as 0.0.0.0/0. The v4-only literal misrouted this to
    sg-ingress-removed in a multi-fault diff, spending RA where the class policy says none."""
    bad = json.dumps({"cidr": "::/0", "from": 22, "proto": "tcp", "to": 22}, sort_keys=True)
    diff = [_e("extra", "sgs", "sg-1", "ingress", actual=bad)]
    assert classify.classify(diff) == "sg-open-world"


def test_route_deleted_and_blackholed():
    gone = BASELINE["route_tables"]["rtb-1"]["routes"][0]
    diff = [_e("missing", "route_tables", "rtb-1", "routes", expected=gone)]
    assert classify.classify(diff) == "route-deleted"
    ops = plan.build(diff, BASELINE)
    assert ops == [{"action": "create_route", "resource_id": "rtb-1",
                    "params": {"RouteTableId": "rtb-1", "DestinationCidrBlock": "0.0.0.0/0",
                               "GatewayId": "igw-1"}}]
    assert policy.evaluate(ops, diff, BASELINE, INVENTORY)["verdict"] == "PASS"

    black = json.dumps({"dest": "0.0.0.0/0", "state": "blackhole", "target": "eni-9"}, sort_keys=True)
    diff2 = [_e("missing", "route_tables", "rtb-1", "routes", expected=gone),
             _e("extra", "route_tables", "rtb-1", "routes", actual=black)]
    assert classify.classify(diff2) == "route-blackholed"
    ops2 = plan.build(diff2, BASELINE)
    assert ops2 == [{"action": "replace_route", "resource_id": "rtb-1",
                     "params": {"RouteTableId": "rtb-1", "DestinationCidrBlock": "0.0.0.0/0",
                                "GatewayId": "igw-1"}}]


def test_nacl_deny_inserted():
    deny = json.dumps({"action": "deny", "cidr": "0.0.0.0/0", "egress": True, "from": None,
                       "proto": "-1", "rule": 50, "to": None}, sort_keys=True)
    diff = [_e("extra", "nacls", "acl-1", "entries", actual=deny)]
    assert classify.classify(diff) == "nacl-deny-inserted"
    ops = plan.build(diff, BASELINE)
    assert ops == [{"action": "delete_network_acl_entry", "resource_id": "acl-1",
                    "params": {"NetworkAclId": "acl-1", "RuleNumber": 50, "Egress": True}}]


def test_rtb_assoc_swapped_uses_runtime_resolution():
    diff = [_e("missing", "route_tables", "rtb-1", "subnets", expected="subnet-1")]
    assert classify.classify(diff) == "rtb-assoc-swapped"
    ops = plan.build(diff, BASELINE)
    assert ops == [{"action": "replace_route_table_association", "resource_id": "rtb-1",
                    "params": {"SubnetId": "subnet-1", "RouteTableId": "rtb-1"}}]


def test_gate_passes_association_swap_across_two_route_tables():
    # a real swap drifts BOTH RTs: subnet-1 missing from its baseline rtb-1, extra on rtb-pub.
    # one replace op fixes both -> completeness must NOT flag the second entry as unremediated.
    base = {**BASELINE, "route_tables": {
        "rtb-1": {"routes": [], "subnets": ["subnet-1"]},
        "rtb-pub": {"routes": [], "subnets": ["subnet-pub"]}}}
    inv = {**INVENTORY, "rt_ids": ["rtb-1", "rtb-pub"]}
    diff = [_e("missing", "route_tables", "rtb-1", "subnets", expected="subnet-1"),
            _e("extra", "route_tables", "rtb-pub", "subnets", actual="subnet-1")]
    ops = plan.build(diff, base)
    assert policy.evaluate(ops, diff, base, inv)["verdict"] == "PASS"


def test_dns_disabled():
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    assert classify.classify(diff) == "dns-disabled"
    ops = plan.build(diff, BASELINE)
    assert ops == [{"action": "modify_vpc_attribute", "resource_id": "vpc-1",
                    "params": {"VpcId": "vpc-1", "EnableDnsSupport": {"Value": True}}}]


def test_eni_sg_swap_converges_to_baseline_set():
    diff = [_e("missing", "enis", "eni-1", "sgs", expected="sg-1"),
            _e("extra", "enis", "eni-1", "sgs", actual="sg-2")]
    assert classify.classify(diff) == "sg-swapped-on-eni"
    ops = plan.build(diff, BASELINE)
    assert ops == [{"action": "modify_network_interface_attribute", "resource_id": "eni-1",
                    "params": {"NetworkInterfaceId": "eni-1", "Groups": ["sg-1"]}}]


def test_gate_blocks_tampered_plan():
    rule = BASELINE["sgs"]["sg-1"]["ingress"][0]
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected=rule)]
    ops = plan.build(diff, BASELINE)
    # attacker widens the fix to 0.0.0.0/0 -- a rule NOT in this SG's baseline
    evil = json.loads(json.dumps(ops))
    evil[0]["params"]["IpPermissions"][0]["IpRanges"][0]["CidrIp"] = "0.0.0.0/0"
    verdict = policy.evaluate(evil, diff, BASELINE, INVENTORY)
    assert verdict["verdict"] == "FAIL"
    assert any("converge-only" in v for v in verdict["violations"])


def test_gate_catches_wrong_target_not_just_shape():
    # THE anti-tautology test: an op that is perfectly shaped (right action, right
    # resource, right diff) but targets a value NOT in baseline must FAIL. The old
    # rebuild-compare gate would have reproduced its own wrong op and passed.
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)  # correct: sets EnableDnsSupport True (baseline)
    assert policy.evaluate(ops, diff, BASELINE, INVENTORY)["verdict"] == "PASS"
    tampered = json.loads(json.dumps(ops))
    tampered[0]["params"]["EnableDnsSupport"]["Value"] = False  # NOT the baseline value
    verdict = policy.evaluate(tampered, diff, BASELINE, INVENTORY)
    assert verdict["verdict"] == "FAIL"
    assert any("converge-only" in v for v in verdict["violations"])


def test_gate_blocks_rogue_extra_op_and_incomplete_plan():
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)
    # rogue op with no corresponding drift: revoke a baseline rule that isn't drifted
    rogue = [*json.loads(json.dumps(ops)), {
        "action": "revoke_security_group_ingress", "resource_id": "sg-1",
        "params": {"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "10.42.0.0/24"}]}]}}]
    verdict = policy.evaluate(rogue, diff, BASELINE, INVENTORY)
    assert verdict["verdict"] == "FAIL"  # removes a baseline rule -> converge-only
    # empty plan against real drift -> incomplete
    empty = policy.evaluate([], diff, BASELINE, INVENTORY)
    assert empty["verdict"] == "FAIL"
    assert any("incomplete" in v for v in empty["violations"])


def test_gate_blocks_non_lab_resource_and_bad_default_route():
    diff = [_e("missing", "route_tables", "rtb-1", "routes",
               expected=json.dumps({"dest": "0.0.0.0/0", "state": "active", "target": "igw-1"}, sort_keys=True))]
    evil = [{"action": "create_route", "resource_id": "rtb-999",
             "params": {"RouteTableId": "rtb-999", "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-666"}}]
    verdict = policy.evaluate(evil, diff, BASELINE, INVENTORY)
    assert verdict["verdict"] == "FAIL"
    assert any("lab-only" in v for v in verdict["violations"])
    assert any("igw-only-default-route" in v for v in verdict["violations"])


def test_gate_blocks_disallowed_action():
    verdict = policy.evaluate([{"action": "terminate_instances", "resource_id": "sg-1", "params": {}}],
                              [], BASELINE, INVENTORY)
    assert verdict["verdict"] == "FAIL"
    assert any("action-allowlist" in v for v in verdict["violations"])


def test_plan_hash_stable():
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)
    assert plan.plan_hash(ops) == plan.plan_hash(json.loads(json.dumps(ops)))


def test_session_policy_covers_only_plan_resources(monkeypatch):
    monkeypatch.setenv("ACCOUNT_ID", "111122223333")
    from shared import sts_scope
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)
    pol = sts_scope.session_policy(ops)
    arns = [r for s in pol["Statement"] if s["Resource"] != "*" for r in s["Resource"]]
    assert arns == ["arn:aws:ec2:us-east-1:111122223333:vpc/vpc-1"]
    actions = {s["Action"] for s in pol["Statement"]}
    assert actions == {"ec2:ModifyVpcAttribute", "ec2:Describe*"}


def test_session_policy_association_includes_subnet(monkeypatch):
    monkeypatch.setenv("ACCOUNT_ID", "111122223333")
    from shared import sts_scope
    diff = [{"kind": "missing", "section": "route_tables", "resource_id": "rtb-1",
             "field": "subnets", "expected": "subnet-1", "actual": None}]
    ops = plan.build(diff, BASELINE)
    pol = sts_scope.session_policy(ops, INVENTORY)
    res = next(s["Resource"] for s in pol["Statement"] if s["Action"] == "ec2:ReplaceRouteTableAssociation")
    assert "arn:aws:ec2:us-east-1:111122223333:route-table/rtb-1" in res
    assert "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-1" in res


def test_session_policy_eni_modify_includes_sgs(monkeypatch):
    monkeypatch.setenv("ACCOUNT_ID", "111122223333")
    from shared import sts_scope
    diff = [{"kind": "missing", "section": "enis", "resource_id": "eni-1", "field": "sgs",
             "expected": "sg-1", "actual": None},
            {"kind": "extra", "section": "enis", "resource_id": "eni-1", "field": "sgs",
             "expected": None, "actual": "sg-2"}]
    ops = plan.build(diff, BASELINE)
    pol = sts_scope.session_policy(ops)
    res = next(s["Resource"] for s in pol["Statement"] if s["Action"] == "ec2:ModifyNetworkInterfaceAttribute")
    assert "arn:aws:ec2:us-east-1:111122223333:network-interface/eni-1" in res
    assert "arn:aws:ec2:us-east-1:111122223333:security-group/sg-1" in res
