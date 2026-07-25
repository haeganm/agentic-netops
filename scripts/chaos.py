"""Chaos seeder: break the lab network in one labeled, precisely-scoped way.

  python scripts/chaos.py --list
  python scripts/chaos.py sg-ingress-removed
  python scripts/chaos.py --restore     # converge everything back to baseline directly
"""
import argparse
import json
import os
import sys
import time

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import baseline as base_mod
from shared import plan as plan_mod

LAB_STACK = os.environ.get("LAB_STACK", "netops-lab")
# ponytail: fixed wait for CloudTrail delivery. Crude but correct; the alternative
# (tailing the trail until quiet) is far more machinery for a cleanup path.
FLUSH_WAIT_S = 150


def outputs() -> dict:
    cfn = boto3.client("cloudformation")
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=LAB_STACK)["Stacks"][0]["Outputs"]}


def seed(fault: str, lab: dict) -> None:
    ec2 = boto3.client("ec2")
    cidr = lab["VpcCidr"]
    if fault == "sg-ingress-removed":
        ec2.revoke_security_group_ingress(GroupId=lab["AnchorPublicSgId"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": cidr}]}])
    elif fault == "sg-open-world":
        ec2.authorize_security_group_ingress(GroupId=lab["AnchorPublicSgId"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    elif fault == "sg-egress-removed":
        ec2.revoke_security_group_egress(GroupId=lab["ProbeSgId"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    elif fault == "route-deleted":
        ec2.delete_route(RouteTableId=lab["PublicRtId"], DestinationCidrBlock="0.0.0.0/0")
    elif fault == "route-blackholed":
        eni = ec2.create_network_interface(SubnetId=lab["PublicSubnetId"],
                                           Description="netops chaos blackhole target")
        eni_id = eni["NetworkInterface"]["NetworkInterfaceId"]
        ec2.replace_route(RouteTableId=lab["PublicRtId"], DestinationCidrBlock="0.0.0.0/0",
                          NetworkInterfaceId=eni_id)
        time.sleep(2)
        ec2.delete_network_interface(NetworkInterfaceId=eni_id)  # route -> blackhole
    elif fault == "nacl-deny-inserted":
        ec2.create_network_acl_entry(NetworkAclId=lab["PrivateNaclId"], RuleNumber=50,
                                     Protocol="-1", RuleAction="deny", Egress=True,
                                     CidrBlock="0.0.0.0/0")
    elif fault == "rtb-assoc-swapped":
        assoc = _assoc_for_subnet(ec2, lab["PrivateSubnetId"])
        ec2.replace_route_table_association(AssociationId=assoc, RouteTableId=lab["PublicRtId"])
    elif fault == "sg-swapped-on-eni":
        ec2.modify_network_interface_attribute(NetworkInterfaceId=lab["AnchorEniPrivateId"],
                                               Groups=[lab["ProbeSgId"]])
    elif fault == "dns-disabled":
        ec2.modify_vpc_attribute(VpcId=lab["VpcId"], EnableDnsSupport={"Value": False})
    else:
        raise SystemExit(f"unknown fault class {fault}")


FAULTS = ["sg-ingress-removed", "sg-open-world", "sg-egress-removed", "route-deleted",
          "route-blackholed", "nacl-deny-inserted", "rtb-assoc-swapped",
          "sg-swapped-on-eni", "dns-disabled"]


def restore(wait_for_flush: bool = True) -> None:
    """Direct converge-to-baseline with caller creds (cleanup path, bypasses the loop).

    Suppresses detection while it works: these mutations are made with the CALLER's identity,
    not the RemediationRole, so the detector would otherwise raise an incident for our own
    cleanup -- and PROVE can snapshot mid-restore and see partial drift. Same maintenance-mode
    trick deploy_lab.ps1 uses for CloudFormation's own changes (ADR 0002).

    NOTE the flush wait: CloudTrail delivery lags ~1-2 min, so maintenance mode must stay on
    past the last event's arrival, not just past the last API call. Pass wait_for_flush=False
    if you are going to seed another fault immediately anyway."""
    table = _table()
    cfg = table.get_item(Key={"pk": "CONFIG", "sk": "BASELINE"})["Item"]
    base = json.loads(cfg["snapshot"])
    inventory = json.loads(cfg["inventory"])
    diff = base_mod.diff(base, base_mod.snapshot(inventory))
    if not diff:
        print("already at baseline")
        return
    table.put_item(Item={"pk": "CONFIG", "sk": "MODE", "mode": "maintenance"})
    ec2 = boto3.client("ec2")
    for op in plan_mod.build(diff, base):
        params = dict(op["params"])
        if op["action"] == "replace_route_table_association":
            params["AssociationId"] = _assoc_for_subnet(ec2, params.pop("SubnetId"))
        getattr(ec2, op["action"])(**params)
        print(f"applied {op['action']} on {op['resource_id']}")
    remaining = base_mod.diff(base, base_mod.snapshot(inventory))
    print(f"restore complete, residual diff: {len(remaining)}")
    if wait_for_flush:
        print(f"  holding detection off {FLUSH_WAIT_S}s while CloudTrail flushes our own changes...")
        time.sleep(FLUSH_WAIT_S)
    table.put_item(Item={"pk": "CONFIG", "sk": "MODE", "mode": "normal"})
    print("  detection re-enabled")


def _assoc_for_subnet(ec2, subnet_id: str) -> str:
    rts = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])["RouteTables"]
    for rt in rts:
        for a in rt.get("Associations", []):
            if a.get("SubnetId") == subnet_id:
                return a["RouteTableAssociationId"]
    raise SystemExit(f"no association found for {subnet_id}")


def _table():
    cfn = boto3.client("cloudformation")
    name = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(
        StackName=os.environ.get("PLATFORM_STACK", "netops-platform"))["Stacks"][0]["Outputs"]}["TableName"]
    return boto3.resource("dynamodb").Table(name)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("fault", nargs="?")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--no-wait", action="store_true",
                    help="skip the CloudTrail flush wait (you are about to seed again)")
    args = ap.parse_args()
    if args.list:
        print("\n".join(FAULTS))
    elif args.restore:
        restore(wait_for_flush=not args.no_wait)
    elif args.fault:
        seed(args.fault, outputs())
        print(f"seeded {args.fault} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    else:
        ap.print_help()
