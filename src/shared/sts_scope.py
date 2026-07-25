"""EXECUTE-stage credential scoping: per-incident session policy narrowed to exactly
the approved plan's actions and resources. Effective permissions are the intersection
role AND permissions-boundary AND this session policy.
"""
import json
import os

import boto3

ACTION_MAP = {
    "authorize_security_group_ingress": ("ec2:AuthorizeSecurityGroupIngress", "security-group"),
    "authorize_security_group_egress": ("ec2:AuthorizeSecurityGroupEgress", "security-group"),
    "revoke_security_group_ingress": ("ec2:RevokeSecurityGroupIngress", "security-group"),
    "revoke_security_group_egress": ("ec2:RevokeSecurityGroupEgress", "security-group"),
    "create_route": ("ec2:CreateRoute", "route-table"),
    "delete_route": ("ec2:DeleteRoute", "route-table"),
    "replace_route": ("ec2:ReplaceRoute", "route-table"),
    "create_network_acl_entry": ("ec2:CreateNetworkAclEntry", "network-acl"),
    "delete_network_acl_entry": ("ec2:DeleteNetworkAclEntry", "network-acl"),
    "replace_route_table_association": ("ec2:ReplaceRouteTableAssociation", "route-table"),
    "replace_network_acl_association": ("ec2:ReplaceNetworkAclAssociation", "network-acl"),
    "modify_vpc_attribute": ("ec2:ModifyVpcAttribute", "vpc"),
    "modify_network_interface_attribute": ("ec2:ModifyNetworkInterfaceAttribute", "network-interface"),
}


def session_policy(ops: list[dict], inventory: dict | None = None) -> dict:
    region = os.environ.get("AWS_REGION", "us-east-1")
    account = os.environ["ACCOUNT_ID"]
    inv = inventory or {}

    def arn(res_type, res_id):
        return f"arn:aws:ec2:{region}:{account}:{res_type}/{res_id}"

    statements = []
    for op in ops:
        iam_action, res_type = ACTION_MAP[op["action"]]
        resources = [arn(res_type, op["resource_id"])]
        if op["action"] == "replace_route_table_association":
            # authorizes against the new RT, the subnet, AND the CURRENT RT (unknown until
            # runtime). Scope to every lab route table + the subnet -- still lab-bounded.
            resources.append(arn("subnet", op["params"]["SubnetId"]))
            resources += [arn("route-table", rt) for rt in inv.get("rt_ids", [])]
        elif op["action"] == "replace_network_acl_association":
            resources.append(arn("subnet", op["params"]["SubnetId"]))
            if inv.get("nacl_id"):
                resources.append(arn("network-acl", inv["nacl_id"]))
        # ModifyNetworkInterfaceAttribute authorizes against the ENI AND each SG applied.
        if op["action"] == "modify_network_interface_attribute" and "Groups" in op["params"]:
            resources += [arn("security-group", g) for g in op["params"]["Groups"]]
        statements.append({"Effect": "Allow", "Action": iam_action,
                           "Resource": sorted(set(resources))})
    # runtime lookups (association ids) are read-only; Describe* takes no resource ARN
    statements.append({"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"})
    return {"Version": "2012-10-17", "Statement": statements}


def scoped_ec2_client(incident_id: str, ops: list[dict], inventory: dict | None = None):
    """Assume RemediationRole with the per-incident session policy; return an EC2 client
    whose credentials can touch nothing but the approved plan's resources."""
    resp = boto3.client("sts").assume_role(
        RoleArn=os.environ["REMEDIATION_ROLE_ARN"],
        # ponytail: truncated to the 64-char API limit. Incident ids are 12 hex chars so
        # this never actually truncates; the slice is belt-and-braces, not a real ceiling.
        RoleSessionName=f"netops-remediation-{incident_id}"[:64],
        Policy=json.dumps(session_policy(ops, inventory)),
        DurationSeconds=900,
    )
    c = resp["Credentials"]
    return boto3.client("ec2", aws_access_key_id=c["AccessKeyId"],
                        aws_secret_access_key=c["SecretAccessKey"],
                        aws_session_token=c["SessionToken"])
