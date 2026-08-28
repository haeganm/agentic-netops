"""Deterministic autonomy tier (ADR 0011). Decides how much human involvement a remediation
needs -- auto-execute (with veto), single approval, or two-party approval -- from the fault,
the ops, the diff, and the oracle verdicts. NEVER the LLM.

Fail-closed: the default is MEDIUM, and LOW is granted only when every signal is clean, so a
misclassification can only ever OVER-escalate (ask for more human oversight), never under.
The tier does not change what the fix does -- the gate still bounds every op to converge to
baseline -- it only changes who signs off.
"""
import json

from shared.policy import WORLD_OPEN  # single source: the gate and the tier must agree

LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
_REMOVING = ("revoke_", "delete_")
_POSTURE = ("replace_", "modify_network_interface_attribute")
_ADDITIVE = ("authorize_", "create_route", "create_network_acl_entry", "modify_vpc_attribute")
# "missing" is synthesized by the planner for an expected-but-never-ledgered oracle (a crashed
# oracle writes nothing, which must escalate, not read as clean); "inconclusive-timeout" is an
# RA analysis still running at the poll ceiling -- same epistemic state as a budget skip.
_BAD_VERDICTS = ("skipped-budget", "inconclusive-timeout", "failed", "error", "missing")


def decide(fault_class: str, ops: list[dict], diff: list[dict], oracle_verdicts: list[dict]) -> tuple:
    """Returns (tier, reasons). reasons = the matched rule strings (ledgered, shown to the
    approver, and cited in the compliance evidence export)."""
    high = _high_reasons(fault_class, ops, diff, oracle_verdicts)
    if high:
        return HIGH, high

    med = _medium_reasons(ops)
    if med:
        return MEDIUM, med

    # LOW requires ALL ops additive/restorative AND clean oracles; else fail closed to MEDIUM.
    non_additive = [op["action"] for op in ops if not op["action"].startswith(_ADDITIVE)]
    if non_additive:
        return MEDIUM, [f"non-additive op(s) {sorted(set(non_additive))}"]
    return LOW, ["all ops additive/restorative; single-resource; oracles clean"]


def _high_reasons(fault_class, ops, diff, verdicts) -> list[str]:
    reasons = []
    if fault_class == "config-drift":
        reasons.append("unknown fault class (config-drift) -> low confidence")

    resource_ids = {e.get("resource_id") for e in diff}
    sections = {e.get("section") for e in diff}
    if len(resource_ids) > 1 or len(sections) > 1:
        reasons.append(f"broad blast radius ({len(resource_ids)} resources, {len(sections)} sections)")

    # world-open that matters = a security-group INGRESS open to the world (the classic
    # inbound exposure). A route or egress to 0.0.0.0/0 is routine routing, not exposure.
    if fault_class == "sg-open-world" or _ingress_world_open(ops, diff):
        reasons.append("security-group ingress open to the world (0.0.0.0/0 or ::/0)")

    bad = [v for v in verdicts if v.get("verdict") in _BAD_VERDICTS]
    if bad:
        reasons.append(f"oracle failure/skip: {[v.get('verdict') for v in bad]}")
    # intent vs CFN contradiction: drift exists but CFN reports the stack in sync
    for v in verdicts:
        if v.get("stack_drift") == "IN_SYNC" and diff:
            reasons.append("intent/CFN disagreement (diff present, CFN IN_SYNC)")
            break
    return reasons


def _medium_reasons(ops) -> list[str]:
    posture = [op["action"] for op in ops
               if op["action"].startswith(_REMOVING) or op["action"].startswith(_POSTURE)]
    if posture:
        return [f"removes/tightens or changes posture: {sorted(set(posture))}"]
    return []


def _ingress_world_open(ops, diff) -> bool:
    blobs = [json.dumps(op.get("params", {}), default=str)
             for op in ops if "security_group_ingress" in op.get("action", "")]
    blobs += [str(e.get("expected")) + str(e.get("actual"))
              for e in diff if e.get("section") == "sgs" and e.get("field") == "ingress"]
    return any(w in b for b in blobs for w in WORLD_OPEN)
