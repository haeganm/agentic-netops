"""Capture the declared baseline after a lab deploy, and seed config items.

Usage:
  python scripts/seed_baseline.py                  # full seed: baseline + RA limits + MODE=normal
  python scripts/seed_baseline.py --mode maintenance   # only flip the detector mode
  python scripts/seed_baseline.py --autonomy manual    # kill-switch: no LOW-tier auto-execute
  python scripts/seed_baseline.py --approver a@x.com=arn:aws:iam::ACCT:user/a   # SoD mapping
"""
import argparse
import json
import os
import sys
import time

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import baseline

LAB_STACK = os.environ.get("LAB_STACK", "netops-lab")
PLATFORM_STACK = os.environ.get("PLATFORM_STACK", "netops-platform")


def stack_outputs(name: str) -> dict:
    cfn = boto3.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["maintenance", "normal"],
                    help="detector suppression during lab deploys")
    ap.add_argument("--autonomy", choices=["normal", "manual"],
                    help="kill-switch: 'manual' forces every LOW-tier auto-execute to a human (ADR 0011)")
    ap.add_argument("--approver", action="append", metavar="EMAIL=IAM_ARN",
                    help="map a console operator to the IAM principal they act as, so an approver "
                         "who caused the drift can be blocked (SoD, ADR 0013). Repeatable.")
    args = ap.parse_args()

    table_name = stack_outputs(PLATFORM_STACK)["TableName"]
    table = boto3.resource("dynamodb").Table(table_name)

    # single-purpose flags: flip one config item and exit
    if args.mode:
        table.put_item(Item={"pk": "CONFIG", "sk": "MODE", "mode": args.mode})
        print(f"MODE={args.mode}")
        return
    if args.autonomy:
        table.put_item(Item={"pk": "CONFIG", "sk": "AUTONOMY", "mode": args.autonomy})
        print(f"AUTONOMY={args.autonomy}"
              + ("  (LOW-tier auto-execute disabled)" if args.autonomy == "manual" else ""))
        return
    if args.approver:
        for pair in args.approver:
            if "=" not in pair:
                raise SystemExit(f"--approver expects EMAIL=IAM_ARN, got {pair!r}")
        new = dict(pair.split("=", 1) for pair in args.approver)
        # MERGE into the existing map: a replace here silently un-mapped every operator not
        # named on this invocation, quietly disabling segregation of duties for them
        existing = (table.get_item(Key={"pk": "CONFIG", "sk": "APPROVERS"})
                    .get("Item", {}) or {}).get("map", {})
        mapping = {**existing, **new}
        table.put_item(Item={"pk": "CONFIG", "sk": "APPROVERS", "map": mapping})
        print(f"APPROVERS updated: {sorted(new)} (full map now: {sorted(mapping)})")
        return

    lab = stack_outputs(LAB_STACK)
    inventory = {
        "vpc_id": lab["VpcId"],
        "sg_ids": [lab["ProbeSgId"], lab["AnchorPublicSgId"], lab["AnchorPrivateSgId"]],
        "rt_ids": [lab["PublicRtId"], lab["PrivateRtId"]],
        "nacl_id": lab["PrivateNaclId"],
        "subnet_ids": [lab["PublicSubnetId"], lab["PrivateSubnetId"]],
        "eni_ids": [lab["AnchorEniPublicId"], lab["AnchorEniPrivateId"]],
        "igw_id": lab["IgwId"],
        "paths": {"private_to_public": lab["PathPrivateToPublicId"],
                  "public_to_igw": lab["PathPublicToIgwId"]},
    }
    snap = baseline.snapshot(inventory)
    table.put_item(Item={
        "pk": "CONFIG", "sk": "BASELINE",
        "snapshot": json.dumps(snap),
        "inventory": json.dumps(inventory),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    # seed RA cap only if absent -- never reset `used` (ADR 0005). Own partition so only
    # the oracles function (not every runtime role) can write it (ADR 0010).
    try:
        table.put_item(Item={"pk": "LIMITS#RA", "sk": "COUNTER", "used": 0, "cap": 30},
                       ConditionExpression="attribute_not_exists(pk)")
        print("RA budget counter seeded (used=0, cap=30)")
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        pass
    table.put_item(Item={"pk": "CONFIG", "sk": "MODE", "mode": "normal"})
    # Governance config must EXIST from the first deploy, or the controls that read it are
    # silently inert: an absent APPROVERS map makes the SoD check unable to ever fire, and an
    # absent AUTONOMY item leaves no supported way to engage the kill-switch. Seed if absent,
    # never overwrite an operator's map.
    for sk, item in (("AUTONOMY", {"mode": "normal"}), ("APPROVERS", {"map": {}})):
        try:
            table.put_item(Item={"pk": "CONFIG", "sk": sk, **item},
                           ConditionExpression="attribute_not_exists(sk)")
            print(f"CONFIG#{sk} seeded ({item})")
        except table.meta.client.exceptions.ConditionalCheckFailedException:
            pass
    n = sum(len(v) for v in snap.values())
    print(f"baseline captured: {n} resources across {len(snap)} sections -> {table_name}")
    if not (table.get_item(Key={"pk": "CONFIG", "sk": "APPROVERS"}).get("Item", {}).get("map")):
        print("NOTE: APPROVERS map is empty -> the segregation-of-duties check cannot fire. "
              "Map operators with: seed_baseline.py --approver you@x.com=arn:aws:iam::ACCT:user/you")


if __name__ == "__main__":
    main()
