"""GENERATE-REPAIR: deterministic converge-to-baseline planner. Every op's target value
comes from the baseline snapshot -- the planner cannot express any other fix.

Op shape: {"action": "<boto3 ec2 method>", "resource_id": "...", "params": {...}}
Ops with runtime lookups (association ids) carry logical params the executor resolves.
"""
import hashlib
import json


def build(diff: list[dict], baseline: dict) -> list[dict]:
    ops = []
    # pair same-destination route missing/extra into replace_route
    route_replaced = set()
    by_rt = {}
    for e in diff:
        if e["section"] == "route_tables" and e["field"] == "routes":
            by_rt.setdefault(e["resource_id"], []).append(e)
    for rt_id, entries in by_rt.items():
        missing = {json.loads(e["expected"])["dest"]: e for e in entries if e["kind"] == "missing"}
        extra = {json.loads(e["actual"])["dest"]: e for e in entries if e["kind"] == "extra"}
        for dest in missing.keys() & extra.keys():
            item = json.loads(missing[dest]["expected"])
            if _unrestorable_route(item):
                continue
            ops.append(_route_op("replace_route", rt_id, item))
            route_replaced.add((rt_id, dest))

    for e in diff:
        section, rid, field, kind = e["section"], e["resource_id"], e["field"], e["kind"]

        if section == "sgs":
            rule = json.loads(e["expected"] if kind == "missing" else e["actual"])
            verb = "authorize" if kind == "missing" else "revoke"
            direction = "ingress" if field == "ingress" else "egress"
            ops.append({"action": f"{verb}_security_group_{direction}", "resource_id": rid,
                        "params": {"GroupId": rid, "IpPermissions": [_perm(rule)]}})

        elif section == "route_tables" and field == "routes":
            item = json.loads(e["expected"] or e["actual"])
            if (rid, item.get("dest")) in route_replaced:
                continue
            if kind == "missing":
                # A gateway-VPC-endpoint route cannot be re-created by any op this planner
                # may emit (ec2:CreateRoute takes VpcEndpointId only for GWLB endpoints; the
                # real API is modify_vpc_endpoint, deliberately outside the action set).
                # Emit nothing: the gate then blocks the plan with an honest "unsupported"
                # reason instead of a misleading converge-only failure. Deleting a rogue
                # endpoint route (the 'extra' side) still works via delete_route.
                if _unrestorable_route(item):
                    continue
                ops.append(_route_op("create_route", rid, item))
            else:
                ops.append(_route_op("delete_route", rid, item, delete=True))

        elif section == "route_tables" and field == "subnets":
            if kind == "missing":  # baseline says this subnet belongs on this route table
                ops.append({"action": "replace_route_table_association", "resource_id": rid,
                            "params": {"SubnetId": e["expected"], "RouteTableId": rid}})

        elif section == "nacls" and field == "entries":
            item = json.loads(e["expected"] or e["actual"])
            if kind == "extra":
                ops.append({"action": "delete_network_acl_entry", "resource_id": rid,
                            "params": {"NetworkAclId": rid, "RuleNumber": item["rule"],
                                       "Egress": item["egress"]}})
            else:
                ops.append({"action": "create_network_acl_entry", "resource_id": rid,
                            "params": _nacl_params(rid, item)})

        elif section == "nacls" and field == "subnets" and kind == "missing":
            ops.append({"action": "replace_network_acl_association", "resource_id": rid,
                        "params": {"SubnetId": e["expected"], "NetworkAclId": rid}})

        elif section == "vpc":
            attr = "EnableDnsSupport" if field == "dns_support" else "EnableDnsHostnames"
            ops.append({"action": "modify_vpc_attribute", "resource_id": rid,
                        "params": {"VpcId": rid, attr: {"Value": e["expected"]}}})

        elif section == "enis" and field == "sgs":
            # set-valued: converge to the full baseline group list in one op
            target = baseline["enis"][rid]["sgs"]
            op = {"action": "modify_network_interface_attribute", "resource_id": rid,
                  "params": {"NetworkInterfaceId": rid, "Groups": target}}
            if op not in ops:
                ops.append(op)

    # safe-first: restore/grant (authorize, create, modify) before removals (revoke,
    # delete), so a partial apply errs toward restored connectivity, not a stranded lab.
    # Stable sort preserves the built order within each rank (keeps replace-route pairing).
    ops.sort(key=lambda o: 1 if o["action"].startswith(("revoke_", "delete_")) else 0)
    return ops


def _unrestorable_route(item: dict) -> bool:
    """True for routes whose re-creation is outside the remediation action set (see the
    comment at the create_route call site). policy.evaluate names the same predicate when
    explaining the resulting block."""
    return (item.get("target") or "").startswith("vpce-")


def plan_hash(ops: list[dict]) -> str:
    return hashlib.sha256(json.dumps(ops, sort_keys=True).encode()).hexdigest()[:16]


def _perm(rule: dict) -> dict:
    perm = {"IpProtocol": rule["proto"]}
    if rule.get("from") is not None:
        perm["FromPort"], perm["ToPort"] = rule["from"], rule["to"]
    if rule.get("cidr"):
        if ":" in rule["cidr"]:
            perm["Ipv6Ranges"] = [{"CidrIpv6": rule["cidr"]}]
        else:
            perm["IpRanges"] = [{"CidrIp": rule["cidr"]}]
    if rule.get("sg"):
        perm["UserIdGroupPairs"] = [{"GroupId": rule["sg"]}]
    if rule.get("pl"):
        perm["PrefixListIds"] = [{"PrefixListId": rule["pl"]}]
    return perm


def _route_op(action: str, rt_id: str, item: dict, delete: bool = False) -> dict:
    params = {"RouteTableId": rt_id}
    dest = item["dest"]
    if dest and dest.startswith("pl-"):
        params["DestinationPrefixListId"] = dest
    else:
        params["DestinationCidrBlock"] = dest
    if not delete:
        target = item.get("target") or ""
        if target.startswith("igw-"):
            params["GatewayId"] = target
        elif target.startswith("eni-"):
            params["NetworkInterfaceId"] = target
        elif target.startswith("vpce-"):
            params["VpcEndpointId"] = target
        else:
            params["GatewayId"] = target  # local etc. -- gate rejects anything unexpected
    return {"action": action, "resource_id": rt_id, "params": params}


def _nacl_params(nacl_id: str, item: dict) -> dict:
    p = {"NetworkAclId": nacl_id, "RuleNumber": item["rule"], "Protocol": str(item["proto"]),
         "RuleAction": item["action"], "Egress": item["egress"], "CidrBlock": item["cidr"]}
    if item.get("from") is not None:
        p["PortRange"] = {"From": item["from"], "To": item["to"]}
    return p
