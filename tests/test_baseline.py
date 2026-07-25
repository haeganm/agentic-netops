"""The intent oracle against a moto-built lab topology: snapshot shape, clean re-diff,
and one detected drift per mutated section."""
import boto3
import pytest
from moto import mock_aws

from shared import baseline


@pytest.fixture()
def lab():
    with mock_aws():
        ec2 = boto3.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.42.0.0/24")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.42.0.0/26")["Subnet"]["SubnetId"]
        igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
        rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)
        sg = ec2.create_security_group(GroupName="probe", Description="probe", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.42.0.0/24"}]}])
        nacl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
        ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=100, Protocol="6",
                                     RuleAction="allow", Egress=True, CidrBlock="0.0.0.0/0",
                                     PortRange={"From": 443, "To": 443})
        eni = ec2.create_network_interface(SubnetId=subnet, Groups=[sg])["NetworkInterface"]["NetworkInterfaceId"]
        inventory = {"vpc_id": vpc, "sg_ids": [sg], "rt_ids": [rt], "nacl_id": nacl,
                     "subnet_ids": [subnet], "eni_ids": [eni]}
        yield ec2, inventory


def test_snapshot_shape_and_clean_diff(lab):
    _, inv = lab
    snap = baseline.snapshot(inv)
    assert snap["vpc"][inv["vpc_id"]]["dns_support"] is True
    assert len(snap["sgs"][inv["sg_ids"][0]]["ingress"]) == 1
    assert any('"dest": "0.0.0.0/0"' in r for r in snap["route_tables"][inv["rt_ids"][0]]["routes"])
    # identical snapshots -> empty diff (the VERIFY exit criterion)
    assert baseline.diff(snap, baseline.snapshot(inv)) == []


def test_diff_sg_rule_removed(lab):
    ec2, inv = lab
    base = baseline.snapshot(inv)
    ec2.revoke_security_group_ingress(GroupId=inv["sg_ids"][0], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.42.0.0/24"}]}])
    d = baseline.diff(base, baseline.snapshot(inv))
    assert len(d) == 1
    assert d[0]["kind"] == "missing" and d[0]["section"] == "sgs" and d[0]["field"] == "ingress"
    assert '"cidr": "10.42.0.0/24"' in d[0]["expected"]


def test_diff_sg_open_world_added(lab):
    ec2, inv = lab
    base = baseline.snapshot(inv)
    ec2.authorize_security_group_ingress(GroupId=inv["sg_ids"][0], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    d = baseline.diff(base, baseline.snapshot(inv))
    assert len(d) == 1 and d[0]["kind"] == "extra" and '"cidr": "0.0.0.0/0"' in d[0]["actual"]


def test_diff_route_deleted(lab):
    ec2, inv = lab
    base = baseline.snapshot(inv)
    ec2.delete_route(RouteTableId=inv["rt_ids"][0], DestinationCidrBlock="0.0.0.0/0")
    d = baseline.diff(base, baseline.snapshot(inv))
    assert len(d) == 1 and d[0]["kind"] == "missing" and d[0]["section"] == "route_tables"


def test_diff_nacl_entry_inserted(lab):
    ec2, inv = lab
    base = baseline.snapshot(inv)
    ec2.create_network_acl_entry(NetworkAclId=inv["nacl_id"], RuleNumber=50, Protocol="-1",
                                 RuleAction="deny", Egress=True, CidrBlock="0.0.0.0/0")
    d = baseline.diff(base, baseline.snapshot(inv))
    assert len(d) == 1 and d[0]["kind"] == "extra" and '"action": "deny"' in d[0]["actual"]


def test_diff_dns_disabled(lab):
    ec2, inv = lab
    base = baseline.snapshot(inv)
    ec2.modify_vpc_attribute(VpcId=inv["vpc_id"], EnableDnsSupport={"Value": False})
    d = baseline.diff(base, baseline.snapshot(inv))
    assert len(d) == 1 and d[0]["kind"] == "changed" and d[0]["field"] == "dns_support"
    assert d[0]["expected"] is True and d[0]["actual"] is False


def test_diff_eni_sg_swapped(lab):
    ec2, inv = lab
    base = baseline.snapshot(inv)
    sg2 = ec2.create_security_group(GroupName="other", Description="other", VpcId=inv["vpc_id"])["GroupId"]
    ec2.modify_network_interface_attribute(NetworkInterfaceId=inv["eni_ids"][0], Groups=[sg2])
    d = baseline.diff(base, baseline.snapshot(inv))
    kinds = {e["kind"] for e in d}
    assert {"missing", "extra"} == kinds and all(e["section"] == "enis" for e in d)
