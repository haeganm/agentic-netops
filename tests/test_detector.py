"""Detector filtering, correlation, idempotency, and suppression paths."""
import json

import pytest

from functions.detector import handler
from shared import ddb


def _sqs_event(event_name="RevokeSecurityGroupIngress", resource="sg-aaa111", *,
               event_id="evt-1", actor="arn:aws:iam::1:user/haegan-admin"):
    detail = {"eventName": event_name, "eventID": event_id,
              "eventTime": "2026-07-24T12:00:00Z",
              "userIdentity": {"arn": actor},
              "requestParameters": {"groupId": resource}}
    return {"Records": [{"messageId": "m1", "body": json.dumps({"detail": detail})}]}


@pytest.fixture()
def table(netops_table, monkeypatch):
    """Detector needs its identity env + seeded config on top of the canonical table."""
    monkeypatch.setenv("REMEDIATION_ROLE_ARN", "arn:aws:iam::1:role/RemediationRole")
    monkeypatch.delenv("STATE_MACHINE_ARN", raising=False)
    ddb.put_config("BASELINE", {"inventory": json.dumps({"sg_ids": ["sg-aaa111"], "vpc_id": "vpc-bbb222"})})
    ddb.put_config("MODE", {"mode": "normal"})
    return netops_table


def test_lab_event_creates_one_incident(table):
    assert handler.lambda_handler(_sqs_event(), None) == {"batchItemFailures": []}
    incidents = ddb.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]["status"] == "DETECTED"
    assert incidents[0]["resource_ids"] == ["sg-aaa111"]


def test_replayed_event_is_idempotent(table):
    handler.lambda_handler(_sqs_event(), None)
    # second copy of the same burst correlates into the open incident, no new one
    handler.lambda_handler(_sqs_event(event_id="evt-2"), None)
    assert len(ddb.list_incidents()) == 1
    iid = ddb.list_incidents()[0]["pk"].split("#")[1]
    assert len(ddb.query_ledger(iid)) == 2  # both events ledgered on the one incident


def test_non_lab_resource_skipped(table):
    handler.lambda_handler(_sqs_event(resource="sg-zzz999"), None)
    assert ddb.list_incidents() == []


def test_remediation_session_skipped(table):
    # the platform's OWN remediation role -> correctly skipped
    handler.lambda_handler(
        _sqs_event(actor="arn:aws:sts::1:assumed-role/RemediationRole/netops-remediation-abc123"), None)
    assert ddb.list_incidents() == []


def test_forged_session_name_is_NOT_skipped(table):
    # SECURITY REGRESSION: an attacker naming their OWN role's session
    # "netops-remediation-evil" must NOT suppress detection (the old substring bug).
    handler.lambda_handler(
        _sqs_event(actor="arn:aws:sts::1:assumed-role/AttackerRole/netops-remediation-evil"), None)
    assert len(ddb.list_incidents()) == 1  # incident IS raised


def test_post_prove_incident_not_absorbed(table):
    # a second fault after the first has moved past DETECTED gets its OWN incident
    handler.lambda_handler(_sqs_event(event_id="evt-a"), None)
    iid = ddb.list_incidents()[0]["pk"].split("#")[1]
    ddb.update_incident(iid, status="PROVING")
    handler.lambda_handler(_sqs_event(event_id="evt-b"), None)
    assert len(ddb.list_incidents()) == 2  # not absorbed into the proving incident


def test_maintenance_mode_skipped(table):
    ddb.put_config("MODE", {"mode": "maintenance"})
    handler.lambda_handler(_sqs_event(), None)
    assert ddb.list_incidents() == []


def test_bad_message_reported_as_partial_failure(table):
    event = {"Records": [{"messageId": "bad", "body": "not json"}]}
    assert handler.lambda_handler(event, None) == {"batchItemFailures": [{"itemIdentifier": "bad"}]}
