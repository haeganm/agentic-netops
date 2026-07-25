"""Prove the tag-scoped remediation boundary live -- the check docs/SECURITY.md has demanded
since it was written, and ADR 0010 still lists as open.

  python scripts/verify_boundary.py        # read-only, mutates nothing, costs nothing

Claim under test: RemediationRole may mutate ONLY resources tagged Project=agentic-netops, only
in us-east-1, and only the executor may wield it. Reading the policy proves none of that:
`aws:ResourceTag` support varies per EC2 action, so a condition that looks right can fail open.

WHY THIS IS NOT AN assume-role PROBE. The obvious test -- assume RemediationRole and try to
mutate an untagged resource -- is impossible by design: the trust policy admits ONLY
ExecutorFunctionRole, so not even the account admin can assume it (asserted below as check 3).
That is the control working, and it means SECURITY.md's original procedure was unrunnable as
written. The claim decomposes into three parts that ARE each provable:

  1. POLICY LOGIC -- for every mutating action, simulate the role with an explicit resource-tag
     context: correct tag => allowed; wrong tag, absent tag (an untagged resource), and wrong
     region => denied. This exercises the real deployed boundary document per action, which is
     what varies.
  2. LIVE TAGGING -- every lab resource the planner can target actually carries the tag. (1)
     without (2) would be a correct policy guarding mistagged resources.
  3. TRUST -- the role is not assumable by anyone but the executor.

(1) + (2) + (3), plus the recorded 9/9 end-to-end remediation runs in docs/evals.md, cover the
documented claim without weakening anything to test it.

Exit 0 = boundary behaves as documented; 1 = it does not.
"""
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import sts_scope

PLATFORM_STACK = os.environ.get("PLATFORM_STACK", "netops-platform")
REGION = "us-east-1"
TAG_KEY, TAG_VALUE = "Project", "agentic-netops"
ACCOUNT = boto3.client("sts").get_caller_identity()["Account"]

# ModifyVpcAttribute ignores aws:ResourceTag, so the boundary pins it to the lab VPC ARN
# instead (ADR 0010). It is verified separately -- tag context is meaningless for it.
ARN_PINNED = {"ec2:ModifyVpcAttribute"}
iam = boto3.client("iam")


def _outputs(stack: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in boto3.client("cloudformation")
            .describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}


def _simulate(role: str, action: str, resource_arn: str, region=REGION, tag=TAG_VALUE) -> str:
    ctx = [{"ContextKeyName": "aws:RequestedRegion", "ContextKeyType": "string",
            "ContextKeyValues": [region]}]
    if tag is not None:
        ctx.append({"ContextKeyName": f"aws:ResourceTag/{TAG_KEY}", "ContextKeyType": "string",
                    "ContextKeyValues": [tag]})
    return iam.simulate_principal_policy(
        PolicySourceArn=role, ActionNames=[action], ResourceArns=[resource_arn],
        ContextEntries=ctx)["EvaluationResults"][0]["EvalDecision"]


def _check_policy_logic(role: str, inv: dict, rows: list) -> bool:
    """Each action must be simulated against ITS OWN resource type: IAM denies
    ec2:CreateRoute on a security-group ARN regardless of tags, which would look like the
    boundary working while actually testing nothing."""
    ok = True
    # one representative live lab resource per resource type the planner can target
    sample = {"security-group": inv["sg_ids"][0], "route-table": inv["rt_ids"][0],
              "network-acl": inv["nacl_id"], "network-interface": inv["eni_ids"][0],
              "vpc": inv["vpc_id"]}
    for action, res_type in sorted({v for v in sts_scope.ACTION_MAP.values()}):
        if action in ARN_PINNED:
            continue
        target = f"arn:aws:ec2:{REGION}:{ACCOUNT}:{res_type}/{sample[res_type]}"
        allowed = _simulate(role, action, target)
        untagged = _simulate(role, action, target, tag=None)
        wrong_tag = _simulate(role, action, target, tag="not-the-lab")
        bad_region = _simulate(role, action, target, region="us-west-2")
        good = (allowed == "allowed" and untagged != "allowed"
                and wrong_tag != "allowed" and bad_region != "allowed")
        ok &= good
        rows.append((f"{action.split(':')[1]} on {res_type}", good,
                     f"tagged={allowed} untagged={untagged} wrongtag={wrong_tag} "
                     f"otherregion={bad_region}"))

    # the ARN-pinned exception: the lab VPC is reachable, another VPC id is not
    lab_vpc = f"arn:aws:ec2:{REGION}:{ACCOUNT}:vpc/{inv['vpc_id']}"
    other_vpc = f"arn:aws:ec2:{REGION}:{ACCOUNT}:vpc/vpc-00000000000000000"
    mine = _simulate(role, "ec2:ModifyVpcAttribute", lab_vpc, tag=None)
    theirs = _simulate(role, "ec2:ModifyVpcAttribute", other_vpc, tag=None)
    good = mine == "allowed" and theirs != "allowed"
    ok &= good
    rows.append(("ModifyVpcAttribute (ARN-pinned)", good,
                 f"labvpc={mine} othervpc={theirs}"))
    return ok


def _check_live_tagging(inv: dict, rows: list) -> bool:
    """A correct policy guarding mistagged resources would still fail closed on a real repair."""
    ec2 = boto3.client("ec2")
    groups = {
        "security-group": ec2.describe_security_groups(GroupIds=inv["sg_ids"])["SecurityGroups"],
        "route-table": ec2.describe_route_tables(RouteTableIds=inv["rt_ids"])["RouteTables"],
        "network-acl": ec2.describe_network_acls(NetworkAclIds=[inv["nacl_id"]])["NetworkAcls"],
        "network-interface": ec2.describe_network_interfaces(
            NetworkInterfaceIds=inv["eni_ids"])["NetworkInterfaces"],
    }
    ok = True
    for kind, items in groups.items():
        missing = [i for i in items
                   if not any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE
                              for t in (i.get("Tags") or i.get("TagSet") or []))]
        good = not missing
        ok &= good
        rows.append((f"{kind}s carry {TAG_KEY}={TAG_VALUE}", good,
                     f"{len(items) - len(missing)}/{len(items)} tagged"))
    return ok


def _check_trust(role_arn: str, rows: list) -> bool:
    """Not even the account admin may assume the remediation role -- only the executor."""
    try:
        boto3.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="netops-trust-probe")
        rows.append(("role NOT assumable by this caller", False, "assume_role SUCCEEDED(!)"))
        return False
    except ClientError as e:
        denied = e.response["Error"]["Code"] == "AccessDenied"
        rows.append(("role NOT assumable by this caller", denied,
                     f"{e.response['Error']['Code']} for {boto3.client('sts')
                        .get_caller_identity()['Arn'].split('/')[-1]}"))
        return denied


def main() -> int:
    plat = _outputs(PLATFORM_STACK)
    role = plat["RemediationRoleArn"]
    os.environ.setdefault("TABLE_NAME", plat["TableName"])
    from shared import ddb
    inv = json.loads(ddb.get_config("BASELINE")["inventory"])

    rows: list = []
    ok = _check_policy_logic(role, inv, rows)
    ok &= _check_live_tagging(inv, rows)
    ok &= _check_trust(role, rows)

    width = max(len(r[0]) for r in rows)
    print(f"\nRemediationRole: {role}")
    print(f"{'-' * (width + 12)}")
    for name, good, detail in rows:
        print(f"  {'PASS' if good else 'FAIL'}  {name:<{width}}  {detail}")
    print(f"{'-' * (width + 12)}")
    print("boundary behaves as documented (policy logic + live tagging + trust)" if ok else
          "BOUNDARY DOES NOT MATCH docs/SECURITY.md")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
