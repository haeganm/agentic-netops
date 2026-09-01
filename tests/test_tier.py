"""Autonomy tier matrix. Fail-closed: default MEDIUM, LOW only when everything is clean,
misclassification can only over-escalate."""
import json

from shared import plan, tier

BASELINE = {
    "sgs": {"sg-1": {"ingress": [json.dumps({"cidr": "10.42.0.0/24", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)], "egress": []}},
    "route_tables": {"rtb-1": {"routes": [json.dumps({"dest": "0.0.0.0/0", "state": "active", "target": "igw-1"}, sort_keys=True)], "subnets": ["subnet-1"]}},
    "nacls": {"acl-1": {"entries": [], "subnets": ["subnet-1"]}},
    "vpc": {"vpc-1": {"dns_support": True, "dns_hostnames": True}},
    "enis": {"eni-1": {"sgs": ["sg-1"]}},
}


def _e(kind, section, rid, field, expected=None, actual=None):
    return {"kind": kind, "section": section, "resource_id": rid, "field": field,
            "expected": expected, "actual": actual}


CLEAN = [{"verdict": "succeeded"}]  # one clean oracle verdict


def test_low_for_pure_restore():
    rule = BASELINE["sgs"]["sg-1"]["ingress"][0]
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected=rule)]
    ops = plan.build(diff, BASELINE)  # single authorize
    t, _ = tier.decide("sg-ingress-removed", ops, diff, CLEAN)
    assert t == tier.LOW


def test_bare_revoke_of_a_non_world_open_rule_is_medium():
    """The plain 'removes access' case: MEDIUM (a human signs off), not LOW and not HIGH."""
    drifted = json.dumps({"cidr": "10.9.9.9/32", "from": 80, "proto": "tcp", "to": 80}, sort_keys=True)
    diff = [_e("extra", "sgs", "sg-1", "ingress", actual=drifted)]
    ops = plan.build(diff, BASELINE)
    assert ops[0]["action"] == "revoke_security_group_ingress"
    t, reasons = tier.decide("sg-ingress-removed", ops, diff, CLEAN)
    assert t == tier.MEDIUM, reasons


def test_intent_cfn_disagreement_forces_high():
    """Drift proven by the differ while CloudFormation reports IN_SYNC = the oracles contradict
    each other, so no autonomy: escalate to two-party."""
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)
    t, reasons = tier.decide("dns-disabled", ops, diff, [{"stack_drift": "IN_SYNC"}])
    assert t == tier.HIGH
    assert any("disagreement" in r for r in reasons), reasons


def test_no_oracle_verdicts_at_all_is_still_decidable():
    """Route classes run no RA and no probe (ADR 0008), so an empty verdict list is normal."""
    gone = BASELINE["route_tables"]["rtb-1"]["routes"][0]
    diff = [_e("missing", "route_tables", "rtb-1", "routes", expected=gone)]
    t, _ = tier.decide("route-deleted", plan.build(diff, BASELINE), diff, [])
    assert t == tier.LOW


def test_world_open_ingress_beats_revoke_and_reaches_high():
    bad = json.dumps({"cidr": "0.0.0.0/0", "from": 22, "proto": "tcp", "to": 22}, sort_keys=True)
    diff = [_e("extra", "sgs", "sg-1", "ingress", actual=bad)]
    ops = plan.build(diff, BASELINE)  # revoke -> removes posture -> but world-open ingress -> HIGH
    t, _ = tier.decide("sg-open-world", ops, diff, CLEAN)
    assert t == tier.HIGH  # world-open ingress escalates above MEDIUM


def test_egress_to_world_restore_is_low_not_high():
    # restoring a baseline EGRESS-to-internet rule is routine (not an inbound exposure) -> LOW
    rule = json.dumps({"cidr": "0.0.0.0/0", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)
    base = {**BASELINE, "sgs": {"sg-1": {"ingress": [], "egress": [rule]}}}
    diff = [_e("missing", "sgs", "sg-1", "egress", expected=rule)]
    ops = plan.build(diff, base)  # authorize egress (additive), egress-to-world != ingress exposure
    t, _ = tier.decide("sg-egress-removed", ops, diff, CLEAN)
    assert t == tier.LOW


def test_route_to_default_is_low_not_high():
    # a default route (dest 0.0.0.0/0) is routing, not exposure -> restore is LOW
    gone = BASELINE["route_tables"]["rtb-1"]["routes"][0]
    diff = [_e("missing", "route_tables", "rtb-1", "routes", expected=gone)]
    ops = plan.build(diff, BASELINE)  # create_route (additive)
    t, _ = tier.decide("route-deleted", ops, diff, CLEAN)
    assert t == tier.LOW


def test_medium_for_nacl_delete():
    deny = json.dumps({"action": "deny", "cidr": "10.42.0.0/24", "egress": True, "from": None,
                       "proto": "-1", "rule": 50, "to": None}, sort_keys=True)
    diff = [_e("extra", "nacls", "acl-1", "entries", actual=deny)]
    ops = plan.build(diff, BASELINE)  # delete_network_acl_entry -> removing -> MEDIUM
    t, _ = tier.decide("nacl-deny-inserted", ops, diff, CLEAN)
    assert t == tier.MEDIUM


def test_high_for_unknown_class():
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)
    t, reasons = tier.decide("config-drift", ops, diff, CLEAN)
    assert t == tier.HIGH
    assert any("unknown fault class" in r for r in reasons)


def test_high_for_broad_blast_radius():
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected="x"),
            _e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    # two sections -> HIGH regardless of op types
    t, reasons = tier.decide("dns-disabled", [{"action": "modify_vpc_attribute", "params": {}}], diff, CLEAN)
    assert t == tier.HIGH
    assert any("blast radius" in r for r in reasons)


def test_high_for_oracle_skip():
    rule = BASELINE["sgs"]["sg-1"]["ingress"][0]
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected=rule)]
    ops = plan.build(diff, BASELINE)
    t, reasons = tier.decide("sg-ingress-removed", ops, diff, [{"verdict": "skipped-budget"}])
    assert t == tier.HIGH
    assert any("oracle" in r for r in reasons)


def test_high_for_inconclusive_timeout():
    """An RA analysis still running at the poll ceiling proved nothing -- the same epistemic
    state as a budget skip, so it must escalate the same way."""
    rule = BASELINE["sgs"]["sg-1"]["ingress"][0]
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected=rule)]
    ops = plan.build(diff, BASELINE)
    t, reasons = tier.decide("sg-ingress-removed", ops, diff, [{"verdict": "inconclusive-timeout"}])
    assert t == tier.HIGH
    assert any("oracle" in r for r in reasons), reasons


def test_high_for_missing_oracle_evidence():
    """A crashed oracle ledgers nothing. The planner synthesizes {"verdict": "missing"} for an
    expected-but-absent oracle; absence of evidence must escalate, not read as clean."""
    rule = BASELINE["sgs"]["sg-1"]["ingress"][0]
    diff = [_e("missing", "sgs", "sg-1", "ingress", expected=rule)]
    ops = plan.build(diff, BASELINE)
    t, reasons = tier.decide("sg-ingress-removed", ops, diff,
                             [{"verdict": "missing", "oracle": "oracle:impact"}])
    assert t == tier.HIGH
    assert any("oracle" in r for r in reasons), reasons


def test_association_swap_is_high_broad_blast_radius():
    """A real rtb-assoc-swapped drifts BOTH route tables (the subnet leaves one and appears on
    the other), so the >1-resource rule escalates it to HIGH -- two-party, not the single
    approval ADR 0011 originally tabled. The ADR was amended (2026-09-01) to match the code:
    tier.py documents over-escalation as the intended fail-closed direction."""
    base = {**BASELINE, "route_tables": {"rtb-1": {"routes": [], "subnets": ["subnet-1"]},
                                         "rtb-2": {"routes": [], "subnets": ["subnet-2"]}}}
    diff = [_e("missing", "route_tables", "rtb-1", "subnets", expected="subnet-1"),
            _e("extra", "route_tables", "rtb-2", "subnets", actual="subnet-1")]
    ops = plan.build(diff, base)
    t, reasons = tier.decide("rtb-assoc-swapped", ops, diff, CLEAN)
    assert t == tier.HIGH
    assert any("blast radius" in r for r in reasons), reasons


def test_dns_disabled_is_low_when_clean():
    diff = [_e("changed", "vpc", "vpc-1", "dns_support", expected=True, actual=False)]
    ops = plan.build(diff, BASELINE)  # modify_vpc_attribute -> additive/enable -> LOW
    t, _ = tier.decide("dns-disabled", ops, diff, CLEAN)
    assert t == tier.LOW
