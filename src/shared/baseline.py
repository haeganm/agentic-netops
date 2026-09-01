"""The intent oracle (ADR 0003): canonical snapshot of the lab network + deterministic diff.

snapshot() describes the live config for a fixed inventory of resource IDs and normalizes
it (sorted rules/routes, only intent-bearing fields). diff() compares two snapshots and
returns machine-readable entries the planner reverts 1:1. No LLM anywhere near this file.
"""
import json

import boto3


def snapshot(inventory: dict) -> dict:
    """inventory: {vpc_id, sg_ids[], rt_ids[], nacl_id, subnet_ids[], eni_ids[]}"""
    ec2 = boto3.client("ec2")
    snap = {"sgs": {}, "route_tables": {}, "nacls": {}, "vpc": {}, "enis": {}}

    for sg in ec2.describe_security_groups(GroupIds=inventory["sg_ids"])["SecurityGroups"]:
        snap["sgs"][sg["GroupId"]] = {
            "ingress": canonical_rules(sg.get("IpPermissions", [])),
            "egress": canonical_rules(sg.get("IpPermissionsEgress", [])),
        }

    for rt in ec2.describe_route_tables(RouteTableIds=inventory["rt_ids"])["RouteTables"]:
        snap["route_tables"][rt["RouteTableId"]] = {
            "routes": sorted(canonical_route(r) for r in rt.get("Routes", [])),
            "subnets": sorted(a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")),
        }

    for nacl in ec2.describe_network_acls(NetworkAclIds=[inventory["nacl_id"]])["NetworkAcls"]:
        snap["nacls"][nacl["NetworkAclId"]] = {
            "entries": sorted(canonical_nacl_entry(e) for e in nacl.get("Entries", []) if e["RuleNumber"] < 32767),
            "subnets": sorted(a["SubnetId"] for a in nacl.get("Associations", [])),
        }

    vpc_id = inventory["vpc_id"]
    snap["vpc"][vpc_id] = {
        "dns_support": ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")["EnableDnsSupport"]["Value"],
        "dns_hostnames": ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")["EnableDnsHostnames"]["Value"],
    }

    for eni in ec2.describe_network_interfaces(NetworkInterfaceIds=inventory["eni_ids"])["NetworkInterfaces"]:
        snap["enis"][eni["NetworkInterfaceId"]] = {
            "sgs": sorted(g["GroupId"] for g in eni.get("Groups", [])),
        }
    return snap


def canonical_rules(perms: list) -> list[str]:
    out = []
    for p in perms:
        base = {"proto": p.get("IpProtocol"), "from": p.get("FromPort"), "to": p.get("ToPort")}
        for r in p.get("IpRanges", []):
            out.append(_c({**base, "cidr": r["CidrIp"]}))
        for r in p.get("Ipv6Ranges", []):
            out.append(_c({**base, "cidr": r["CidrIpv6"]}))
        for g in p.get("UserIdGroupPairs", []):
            out.append(_c({**base, "sg": g["GroupId"]}))
        # prefix-list sources too: a rule granted via a customer-managed prefix list (which
        # can contain 0.0.0.0/0) used to canonicalize to NOTHING, so the drift diffed empty
        # and the incident closed FALSE_POSITIVE while the rule persisted
        for pl in p.get("PrefixListIds", []):
            out.append(_c({**base, "pl": pl["PrefixListId"]}))
    return sorted(out)


def canonical_route(r: dict) -> str:
    dest = r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId")
    # VpcEndpointId included so an op-params dict canonicalizes like the describe output
    # (which reports endpoint routes under GatewayId) instead of to target null
    target = (r.get("GatewayId") or r.get("NetworkInterfaceId") or r.get("NatGatewayId")
              or r.get("TransitGatewayId") or r.get("VpcPeeringConnectionId")
              or r.get("VpcEndpointId"))
    return _c({"dest": dest, "target": target, "state": r.get("State", "active")})


def canonical_nacl_entry(e: dict) -> str:
    pr = e.get("PortRange") or {}
    return _c({"rule": e["RuleNumber"], "proto": e["Protocol"], "action": e["RuleAction"],
               "egress": e["Egress"], "cidr": e.get("CidrBlock"),
               "from": pr.get("From"), "to": pr.get("To")})


def _c(d: dict) -> str:
    """Canonical form: sorted-key JSON string, so lists of rules compare as sets."""
    return json.dumps(d, sort_keys=True, default=str)


def diff(baseline: dict, live: dict) -> list[dict]:
    """Entries: {kind: missing|extra|changed, section, resource_id, field, expected, actual}.
    'missing' = in baseline, not live (revert = re-create); 'extra' = live only (revert = remove)."""
    out = []
    for section in ("sgs", "route_tables", "nacls", "vpc", "enis"):
        for rid, base_res in baseline.get(section, {}).items():
            live_res = live.get(section, {}).get(rid, {})
            for field, base_val in base_res.items():
                live_val = live_res.get(field)
                if base_val == live_val:
                    continue
                if isinstance(base_val, list):
                    want, have = set(base_val), set(live_val or [])
                    for item in sorted(want - have):
                        out.append({"kind": "missing", "section": section, "resource_id": rid,
                                    "field": field, "expected": item, "actual": None})
                    for item in sorted(have - want):
                        out.append({"kind": "extra", "section": section, "resource_id": rid,
                                    "field": field, "expected": None, "actual": item})
                else:
                    out.append({"kind": "changed", "section": section, "resource_id": rid,
                                "field": field, "expected": base_val, "actual": live_val})
    return out
