"""Oracle dispatch, focused on the two ways an impact check can fail to prove anything.
Both used to be reported as evidence of unreachability, which FAILS a correctly-remediated
incident and lies to the auditor."""
import json

import pytest

from functions.oracles import handler
from shared import ddb


@pytest.fixture()
def lab(netops_table, monkeypatch):
    monkeypatch.setenv("LAB_STACK", "netops-lab")
    ddb.put_config("BASELINE", {"inventory": json.dumps(
        {"vpc_id": "vpc-1", "paths": {"private_to_public": "nip-1", "public_to_igw": "nip-2"}})})
    ddb.create_incident("o1", {"status": "PROVING", "gsi1sk": "2026"})
    return netops_table


def _ra_poll(monkeypatch, ra_status, polls, found=False):
    """Drive ra_poll with a stubbed describe response."""
    class _Ec2:
        def describe_network_insights_analyses(self, **kw):
            return {"NetworkInsightsAnalyses": [{"Status": ra_status, "NetworkPathFound": found}]}

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: _Ec2())
    return handler.lambda_handler({"op": "ra_poll", "incident_id": "o1", "id": "nia-1",
                                   "path_key": "private_to_public", "polls": polls,
                                   "stage": "VERIFY"}, None)


def test_ra_poll_reports_a_finished_analysis(lab, monkeypatch):
    out = _ra_poll(monkeypatch, "succeeded", polls=0, found=True)
    assert out["done"] is True and out["started"] is True and out["reachable"] is True
    verdict = json.loads(ddb.query_ledger("o1")[-1]["payload"])
    assert verdict["verdict"] == "succeeded" and verdict["reachable"] is True


def test_ra_poll_exhaustion_is_inconclusive_not_unreachable(lab, monkeypatch):
    """At the poll ceiling a STILL-RUNNING analysis has proven nothing. Reporting
    reachable=false there routed a correctly-remediated incident to MarkFailed."""
    out = _ra_poll(monkeypatch, "running", polls=handler.MAX_POLLS - 1)
    assert out["done"] is True
    assert out["started"] is False       # the ASL's ReRaHealthy? guard routes on this
    assert "reachable" not in out       # never claim a verdict we don't have
    verdict = json.loads(ddb.query_ledger("o1")[-1]["payload"])
    assert verdict["verdict"] == "inconclusive-timeout" and "reachable" not in verdict
    assert ddb.get_incident("o1")["verification"] == "LIMITED"


def test_ra_poll_keeps_polling_below_the_ceiling(lab, monkeypatch):
    out = _ra_poll(monkeypatch, "running", polls=1)
    assert out["done"] is False and "reachable" not in out


def test_ra_start_fails_closed_without_a_budget_counter(lab, monkeypatch):
    """No counter item at all must SKIP the analysis, never run it unbudgeted."""
    out = handler.lambda_handler({"op": "ra_start", "incident_id": "o1",
                                  "path_key": "private_to_public", "stage": "MEASURE"}, None)
    assert out["started"] is False and out["done"] is True
    verdict = json.loads(ddb.query_ledger("o1")[-1]["payload"])
    assert verdict["verdict"] == "skipped-budget"
    assert ddb.get_incident("o1")["verification"] == "LIMITED"


def test_probe_record_ledgers_the_dataplane_verdict(lab):
    out = handler.lambda_handler({"op": "probe_record", "incident_id": "o1", "stage": "VERIFY",
                                  "verdict": {"dns": "pass", "tcp": "pass", "latency_ms": 8}}, None)
    assert out == {"recorded": True, "dns": "pass", "tcp": "pass"}
    entry = ddb.query_ledger("o1")[-1]
    assert entry["actor"] == "oracle:dataplane"


def test_unknown_op_raises(lab):
    with pytest.raises(ValueError, match="unknown op"):
        handler.lambda_handler({"op": "nope", "incident_id": "o1"}, None)
