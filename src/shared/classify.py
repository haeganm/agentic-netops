"""Deterministic fault classification from the baseline diff. This -- not the LLM --
drives control flow (which oracles run, what the eval scores against).
"""
import json

FAULT_CLASSES = [
    "sg-ingress-removed", "sg-open-world", "sg-egress-removed",
    "route-deleted", "route-blackholed", "nacl-deny-inserted",
    "rtb-assoc-swapped", "sg-swapped-on-eni", "dns-disabled",
    "config-drift",  # generic fallback: still proven drift, still remediable
]

# Which MEASURE/VERIFY oracles apply per class -- the single source of truth for oracle
# selection (ADR 0008 names this table). RA only where it can actually adjudicate; probe only
# where the private data path is affected. The RA *budget* cap is a separate concern (ADR 0005).
ORACLE_POLICY = {
    "sg-ingress-removed": {"ra_path": "private_to_public", "probe": False},
    "sg-open-world": {"ra_path": None, "probe": False},
    "sg-egress-removed": {"ra_path": None, "probe": True},
    # Route classes verify by intent + CFN drift only: RA models real internet
    # reachability, and an IGW path from an ENI with no public IP is unreachable
    # even at baseline (verified live) - the $0 lab deliberately has no public IPs.
    "route-deleted": {"ra_path": None, "probe": False},
    "route-blackholed": {"ra_path": None, "probe": False},
    "nacl-deny-inserted": {"ra_path": "private_to_public", "probe": True},
    "rtb-assoc-swapped": {"ra_path": None, "probe": True},
    "sg-swapped-on-eni": {"ra_path": "private_to_public", "probe": False},
    "dns-disabled": {"ra_path": None, "probe": True},
    "config-drift": {"ra_path": None, "probe": True},
}


def classify(diff: list[dict]) -> str:
    """First matching class by specificity. Multi-fault diffs pick the dominant class;
    remediation reverts the whole diff regardless, so classification only steers
    oracle selection and eval scoring."""
    sections = {e["section"] for e in diff}

    if "vpc" in sections:
        return "dns-disabled"
    if "enis" in sections:
        return "sg-swapped-on-eni"

    nacl = [e for e in diff if e["section"] == "nacls"]
    if any(e["kind"] == "extra" and '"action": "deny"' in (e["actual"] or "") for e in nacl):
        return "nacl-deny-inserted"

    rts = [e for e in diff if e["section"] == "route_tables"]
    if any(e["field"] == "subnets" for e in rts):
        return "rtb-assoc-swapped"
    route_entries = [e for e in rts if e["field"] == "routes"]
    if route_entries:
        missing = [e for e in route_entries if e["kind"] == "missing"]
        extra = [e for e in route_entries if e["kind"] == "extra"]
        if missing and extra and _dests(missing) & _dests(extra):
            return "route-blackholed"  # same destination, different/blackholed target
        if missing:
            return "route-deleted"

    sgs = [e for e in diff if e["section"] == "sgs"]
    if any(e["kind"] == "extra" and e["field"] == "ingress"
           and '"cidr": "0.0.0.0/0"' in (e["actual"] or "") for e in sgs):
        return "sg-open-world"
    if any(e["kind"] == "missing" and e["field"] == "ingress" for e in sgs):
        return "sg-ingress-removed"
    if any(e["kind"] == "missing" and e["field"] == "egress" for e in sgs):
        return "sg-egress-removed"

    return "config-drift"


def oracles_for(fault_class: str) -> dict:
    return ORACLE_POLICY.get(fault_class, ORACLE_POLICY["config-drift"])


def _dests(entries: list[dict]) -> set:
    out = set()
    for e in entries:
        item = json.loads(e["expected"] or e["actual"])
        out.add(item.get("dest"))
    return out
