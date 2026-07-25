"""Shared test setup.

The moto DynamoDB table used to be hand-built in seven test files and had already diverged --
four copies omitted GSI1, so those tests exercised a table shape the deployed stack doesn't
have. One canonical fixture here mirrors template.yaml's NetopsTable exactly.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# moto: fake credentials so tests can never touch real AWS
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ.pop("AWS_PROFILE", None)
os.environ.pop("DDB_ENDPOINT", None)

TABLE_NAME = "netops-test"


@pytest.fixture()
def netops_table(monkeypatch):
    """The real table shape (pk/sk + GSI1), inside mock_aws. Yields the boto3 Table."""
    import boto3
    from moto import mock_aws

    monkeypatch.setenv("TABLE_NAME", TABLE_NAME)
    monkeypatch.setenv("ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    with mock_aws():
        yield boto3.resource("dynamodb").create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"},
                                  {"AttributeName": "gsi1pk", "AttributeType": "S"},
                                  {"AttributeName": "gsi1sk", "AttributeType": "S"}],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI1",
                "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"},
                              {"AttributeName": "gsi1sk", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST")


# ---- shared fixture data -------------------------------------------------------------------

INVENTORY = {"vpc_id": "vpc-1", "sg_ids": ["sg-1", "sg-2"], "rt_ids": ["rtb-1"],
             "nacl_id": "acl-1", "subnet_ids": ["subnet-1"], "eni_ids": ["eni-1"],
             "igw_id": "igw-1"}

SG_RULE_443 = json.dumps({"cidr": "10.42.0.0/24", "from": 443, "proto": "tcp", "to": 443},
                         sort_keys=True)
ROUTE_DEFAULT = json.dumps({"dest": "0.0.0.0/0", "state": "active", "target": "igw-1"},
                           sort_keys=True)

BASELINE = {
    "sgs": {"sg-1": {"ingress": [SG_RULE_443], "egress": []}},
    "route_tables": {"rtb-1": {"routes": [ROUTE_DEFAULT], "subnets": ["subnet-1"]}},
    "nacls": {"acl-1": {"entries": [], "subnets": ["subnet-1"]}},
    "vpc": {"vpc-1": {"dns_support": True, "dns_hostnames": True}},
    "enis": {"eni-1": {"sgs": ["sg-1"]}},
}


def diff_entry(kind, section, rid, field, expected=None, actual=None) -> dict:
    """One shared.baseline.diff() entry, as the differ would emit it."""
    return {"kind": kind, "section": section, "resource_id": rid, "field": field,
            "expected": expected, "actual": actual}


def ledger_sk(incident_id: str, seq: int) -> str:
    """The sort key of a specific ledger entry (for tamper tests)."""
    from shared import ddb
    for e in ddb.query_ledger(incident_id):
        if int(e["seq"]) == seq:
            return e["sk"]
    raise KeyError(f"{incident_id} has no ledger entry seq={seq}")


class FakeSfn:
    """Stand-in Step Functions client. Records which token each call received, and exposes the
    full exception set the api handler catches (a partial set only worked because Python
    evaluates `except` tuples lazily)."""

    class exceptions:
        class TaskTimedOut(Exception):
            pass

        class TaskDoesNotExist(Exception):
            pass

        class InvalidToken(Exception):
            pass

    def __init__(self, calls: dict | None = None):
        self.calls = calls if calls is not None else {}

    def send_task_success(self, taskToken, output):
        self.calls["success"] = taskToken

    def send_task_failure(self, taskToken, error, cause):
        self.calls["failure"] = taskToken
        self.calls["error"] = error


@pytest.fixture()
def fake_sfn(monkeypatch):
    """Patch boto3.client so handlers get FakeSfn; yields the shared calls dict."""
    import boto3

    fake = FakeSfn()
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)
    return fake.calls
