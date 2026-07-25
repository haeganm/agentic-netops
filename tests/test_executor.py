"""Executor: the last control before real EC2 mutation. Plan-hash lock, gate re-check,
scoped apply, partial-apply ledger, and _resolve fail-fast."""
import json

import boto3
import pytest
from moto import mock_aws

from functions.executor import handler
from shared import ddb, plan


@pytest.fixture()
def lab(monkeypatch):
    monkeypatch.setenv("TABLE_NAME", "netops-test")
    monkeypatch.setenv("ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    with mock_aws():
        # remediation role the executor assumes
        iam = boto3.client("iam")
        role = iam.create_role(RoleName="RemediationRole",
                               AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                                                  "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        monkeypatch.setenv("REMEDIATION_ROLE_ARN", role)
        ec2 = boto3.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.42.0.0/24")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="anchor", Description="a", VpcId=vpc)["GroupId"]
        # drop moto's default all-egress so the SG matches the empty-egress baseline below
        ec2.revoke_security_group_egress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        rt = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"][0]["RouteTableId"]
        nacl = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkAcls"][0]["NetworkAclId"]
        # table
        boto3.resource("dynamodb").create_table(
            TableName="netops-test",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST")
        inventory = {"vpc_id": vpc, "sg_ids": [sg], "rt_ids": [rt], "nacl_id": nacl,
                     "subnet_ids": [], "eni_ids": [], "igw_id": "igw-x"}
        # baseline: the SG's ingress SHOULD contain the 443 rule (drift removed it)
        rule = json.dumps({"cidr": "10.42.0.0/24", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)
        snap = {"sgs": {sg: {"ingress": [rule], "egress": []}}, "route_tables": {},
                "nacls": {}, "vpc": {}, "enis": {}}
        ddb.put_config("BASELINE", {"snapshot": json.dumps(snap), "inventory": json.dumps(inventory)})
        yield sg


def _authorize_op(sg):
    return {"action": "authorize_security_group_ingress", "resource_id": sg,
            "params": {"GroupId": sg, "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                 "IpRanges": [{"CidrIp": "10.42.0.0/24"}]}]}}


def test_rejects_hash_mismatch(lab):
    ops = [_authorize_op(lab)]
    ddb.create_incident("i1", {"status": "EXECUTING", "plan_hash": "deadbeef", "gsi1sk": "x"})
    with pytest.raises(ValueError, match="hash mismatch"):
        handler.lambda_handler({"incident_id": "i1", "ops": ops}, None)


def test_gate_recheck_blocks_tampered_ops(lab):
    # ops whose hash matches META but that DON'T converge (world-open) -> gate re-check fails
    evil = [{"action": "authorize_security_group_ingress", "resource_id": lab,
             "params": {"GroupId": lab, "IpPermissions": [
                 {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                  "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}}]
    ddb.create_incident("i2", {"status": "EXECUTING", "plan_hash": plan.plan_hash(evil), "gsi1sk": "x"})
    with pytest.raises(ValueError, match="gate re-check failed"):
        handler.lambda_handler({"incident_id": "i2", "ops": evil}, None)


def test_happy_path_applies_and_verifies(lab):
    ops = [_authorize_op(lab)]
    ddb.create_incident("i3", {"status": "EXECUTING", "plan_hash": plan.plan_hash(ops), "gsi1sk": "x"})
    out = handler.lambda_handler({"incident_id": "i3", "ops": ops}, None)
    assert out["applied"] == ["authorize_security_group_ingress"]
    # the rule is now present on the SG
    sgs = boto3.client("ec2").describe_security_groups(GroupIds=[lab])["SecurityGroups"]
    assert any(p["FromPort"] == 443 for p in sgs[0]["IpPermissions"])


def test_resolve_fails_fast_when_no_association(lab):
    ec2 = boto3.client("ec2")
    with pytest.raises(ValueError, match="no association"):
        handler._resolve(ec2, {"action": "replace_route_table_association",
                               "resource_id": "rtb-x",
                               "params": {"SubnetId": "subnet-missing", "RouteTableId": "rtb-x"}})
