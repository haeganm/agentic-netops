"""The deterministic safety gate (ADR 0004). Evaluates a remediation plan BEFORE any
human sees it and independently of whoever produced it. No LLM input reaches this module.

The load-bearing guarantee is CONVERGE-ONLY, checked INDEPENDENTLY of the planner: for
every op, the state it produces must equal the recorded baseline for that exact
resource/field. The gate reconstructs each op's target in the baseline's own canonical
form (via shared.baseline, the intent oracle) and asserts membership/equality against the
baseline snapshot. It deliberately does NOT call plan.build -- a planner bug or a tampered
op that targets a non-baseline value is therefore CAUGHT, not reproduced. Because an
authorize/create op must match that specific resource's baseline, world-open rules (v4 or
v6) that aren't already in the baseline are rejected as a direct consequence.
"""
import json

from shared import baseline as base

POLICY_VERSION = "2.0.0"
MAX_OPS = 20

ALLOWED_ACTIONS = {
    "authorize_security_group_ingress", "authorize_security_group_egress",
    "revoke_security_group_ingress", "revoke_security_group_egress",
    "create_route", "delete_route", "replace_route",
    "create_network_acl_entry", "delete_network_acl_entry",
    "replace_route_table_association", "associate_route_table",
    "replace_network_acl_association",
    "modify_vpc_attribute", "modify_network_interface_attribute",
}

WORLD_OPEN = ("0.0.0.0/0", "::/0")


def evaluate(ops: list[dict], diff: list[dict], baseline: dict, inventory: dict) -> dict:
    """Returns {verdict: PASS|FAIL, violations: [...], policy_version}.

    There is deliberately NO escape hatch. An earlier version accepted an operator-authored
    allowlist that could waive the converge-only rule for a world-open authorize; nothing
    seeded it, nothing tested it, and its exact serialization was undocumented -- i.e. a
    security-gate bypass nobody could audit. The gate is now unconditional.
    """
    violations = []
    known_ids = set(_flat_ids(inventory))

    if len(ops) > MAX_OPS:
        violations.append(f"bounded: {len(ops)} ops > max {MAX_OPS}")

    covered_fields = set()
    for op in ops:
        action = op.get("action")
        rid = op.get("resource_id")
        if action not in ALLOWED_ACTIONS:
            violations.append(f"action-allowlist: {action} not permitted")
            continue
        if rid not in known_ids:
            violations.append(f"lab-only: {rid} not in lab inventory")

        ok, reason, touched = _converges(op, baseline)
        if not ok:
            violations.append(f"converge-only: {action} on {rid} does not converge to baseline ({reason})")
        covered_fields.update(touched)

        # defense-in-depth: a default route may only point at the lab IGW
        if action in ("create_route", "replace_route") \
                and op["params"].get("DestinationCidrBlock") in WORLD_OPEN:
            target = op["params"].get("GatewayId", "")
            if target != inventory.get("igw_id"):
                violations.append(f"igw-only-default-route: {op['params'].get('DestinationCidrBlock')} -> {target}")

    # completeness: every drifted field must be addressed by some op (no left-behind drift)
    for e in diff:
        key = _cover_key(e["section"], e["resource_id"], e["field"], e.get("expected"), e.get("actual"))
        if key not in covered_fields:
            if _unsupported_route_restore(e):
                # honest reason, not a generic "incomplete": the planner deliberately emits
                # no op for this class (plan._unrestorable_route) because the real API,
                # modify_vpc_endpoint, is outside the remediation action set
                violations.append(
                    f"unsupported: restoring the gateway-VPC-endpoint route on {e['resource_id']} "
                    "requires modify_vpc_endpoint (outside the remediation action set) -- human required")
            else:
                violations.append(f"incomplete: drift {e['section']}/{e['resource_id']}/{e['field']} unremediated")

    return {"verdict": "PASS" if not violations else "FAIL",
            "violations": violations, "policy_version": POLICY_VERSION}


def _unsupported_route_restore(e: dict) -> bool:
    if e["section"] != "route_tables" or e["field"] != "routes" or e["kind"] != "missing":
        return False
    try:
        item = json.loads(e["expected"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return False
    from shared.plan import _unrestorable_route
    return _unrestorable_route(item)


def _cover_key(section: str, resource_id: str, field: str, expected=None, actual=None) -> tuple:
    """A subnet association is one logical fact spanning two route tables/NACLs: re-associating
    the subnet fixes the 'missing' on its baseline RT AND the 'extra' on the wrong RT. Key such
    drift by the subnet so a single replace op covers both entries."""
    if field == "subnets":
        return (section, "subnet", expected or actual)
    return (section, resource_id, field)


def _converges(op: dict, baseline: dict) -> tuple[bool, str, set]:
    """Does this op move its resource/field TOWARD the recorded baseline?
    Returns (ok, reason, {(section,resource_id,field) this op touches})."""
    action = op["action"]
    p = op.get("params", {})
    rid = op.get("resource_id")

    if action.startswith("authorize_security_group_"):
        direction = "ingress" if action.endswith("ingress") else "egress"
        want = set(base.canonical_rules(p.get("IpPermissions", [])))
        have = set(baseline.get("sgs", {}).get(rid, {}).get(direction, []))
        # every rule being ADDED must already be in this SG's baseline for this direction
        extra = want - have
        return (not extra, f"adds non-baseline rule(s) {sorted(extra)}" if extra else "",
                {("sgs", rid, direction)})

    if action.startswith("revoke_security_group_"):
        direction = "ingress" if action.endswith("ingress") else "egress"
        want = set(base.canonical_rules(p.get("IpPermissions", [])))
        have = set(baseline.get("sgs", {}).get(rid, {}).get(direction, []))
        # every rule being REMOVED must be absent from baseline (we only strip drift)
        kept = want & have
        return (not kept, f"removes baseline rule(s) {sorted(kept)}" if kept else "",
                {("sgs", rid, direction)})

    if action in ("create_route", "replace_route"):
        canon = base.canonical_route(p)
        have = baseline.get("route_tables", {}).get(rid, {}).get("routes", [])
        return (canon in have, "route target not in baseline" if canon not in have else "",
                {("route_tables", rid, "routes")})

    if action == "delete_route":
        dest = p.get("DestinationCidrBlock") or p.get("DestinationPrefixListId")
        have_dests = {json.loads(r).get("dest") for r in baseline.get("route_tables", {}).get(rid, {}).get("routes", [])}
        # deleting is only valid if baseline has NO route for this destination
        return (dest not in have_dests, f"deletes baseline route {dest}" if dest in have_dests else "",
                {("route_tables", rid, "routes")})

    if action == "create_network_acl_entry":
        canon = base.canonical_nacl_entry(p)
        have = baseline.get("nacls", {}).get(rid, {}).get("entries", [])
        return (canon in have, "nacl entry not in baseline" if canon not in have else "",
                {("nacls", rid, "entries")})

    if action == "delete_network_acl_entry":
        rule = p.get("RuleNumber")
        egress = p.get("Egress")
        have_rules = {(json.loads(e).get("rule"), json.loads(e).get("egress"))
                      for e in baseline.get("nacls", {}).get(rid, {}).get("entries", [])}
        return ((rule, egress) not in have_rules,
                f"deletes baseline nacl rule {rule}" if (rule, egress) in have_rules else "",
                {("nacls", rid, "entries")})

    if action in ("replace_route_table_association", "associate_route_table"):
        subnet = p.get("SubnetId")
        have = baseline.get("route_tables", {}).get(rid, {}).get("subnets", [])
        # one op covers the subnet's association drift on BOTH route tables (see _cover_key);
        # associate is the same converge check -- it applies when no association exists
        return (subnet in have, f"subnet {subnet} not associated to {rid} in baseline" if subnet not in have else "",
                {("route_tables", "subnet", subnet)})

    if action == "replace_network_acl_association":
        subnet = p.get("SubnetId")
        have = baseline.get("nacls", {}).get(rid, {}).get("subnets", [])
        return (subnet in have, f"subnet {subnet} not associated to {rid} in baseline" if subnet not in have else "",
                {("nacls", "subnet", subnet)})

    if action == "modify_vpc_attribute":
        for field, attr in (("dns_support", "EnableDnsSupport"), ("dns_hostnames", "EnableDnsHostnames")):
            if attr in p:
                want = p[attr].get("Value")
                have = baseline.get("vpc", {}).get(rid, {}).get(field)
                return (want == have, f"{attr}={want} != baseline {have}" if want != have else "",
                        {("vpc", rid, field)})
        return (False, "modify_vpc_attribute sets no known attribute", set())

    if action == "modify_network_interface_attribute":
        want = sorted(p.get("Groups", []))
        have = sorted(baseline.get("enis", {}).get(rid, {}).get("sgs", []))
        return (want == have, f"groups {want} != baseline {have}" if want != have else "",
                {("enis", rid, "sgs")})

    return (False, "unhandled action", set())


def _flat_ids(inventory: dict) -> list[str]:
    out = []
    for v in inventory.values():
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


