"""ddb + ledger against moto. conftest guarantees no real AWS is reachable."""
import pytest

from shared import ddb, ledger


def test_create_incident_is_idempotent(netops_table):
    assert ddb.create_incident("abc123", {"status": "PROVING", "gsi1sk": "2026-07-24T00:00:00Z"})
    assert not ddb.create_incident("abc123", {"status": "PROVING", "gsi1sk": "2026-07-24T00:00:00Z"})
    assert ddb.get_incident("abc123")["status"] == "PROVING"


def test_update_incident_handles_reserved_words(netops_table):
    ddb.create_incident("abc123", {"status": "PROVING", "gsi1sk": "2026-07-24T00:00:00Z"})
    ddb.update_incident("abc123", status="RESOLVED", plan_hash="deadbeef", tokens=42)
    item = ddb.get_incident("abc123")
    assert item["status"] == "RESOLVED" and item["tokens"] == 42


def test_list_incidents_newest_first(netops_table):
    ddb.create_incident("a", {"status": "PROVING", "gsi1sk": "2026-07-24T01:00:00Z"})
    ddb.create_incident("b", {"status": "PROVING", "gsi1sk": "2026-07-24T02:00:00Z"})
    assert [i["pk"] for i in ddb.list_incidents()] == ["INCIDENT#b", "INCIDENT#a"]


def test_ra_budget_fail_closed_and_cap(netops_table):
    # no counter item at all -> refuse (fail-closed)
    assert not ddb.consume_ra_budget()
    ddb.put_ra_budget(used=0, cap=2)
    assert ddb.consume_ra_budget()
    assert ddb.consume_ra_budget()
    assert not ddb.consume_ra_budget()  # cap reached
    assert ddb.get_ra_budget()["used"] == 2


def test_ledger_append_and_query(netops_table):
    ledger.append("abc123", "PROVE", "oracle_verdict", "oracle:intent", {"diff_count": 3})
    ledger.append("abc123", "MEASURE", "oracle_verdict", "oracle:impact", {"reachable": False})
    entries = ddb.query_ledger("abc123")
    assert len(entries) == 2
    assert entries[0]["stage"] == "PROVE" and entries[0]["actor"] == "oracle:intent"
    assert not entries[0]["truncated"]


def test_ledger_clamps_payload(netops_table):
    ledger.append("abc123", "PROVE", "event", "system", {"blob": "x" * 20000})
    entry = ddb.query_ledger("abc123")[0]
    assert len(entry["payload"]) == ledger.MAX_PAYLOAD and entry["truncated"]


def test_ledger_rejects_unknown_stage(netops_table):
    with pytest.raises(AssertionError):
        ledger.append("abc123", "GUESS", "event", "system", {})
