"""Tamper-evident hash-chained ledger: valid on clean append, breaks on any
alteration / insertion / deletion, at the correct first_break_seq."""
from conftest import ledger_sk

from shared import ddb, ledger


def _chain(iid):
    ledger.append(iid, "DETECT", "event", "system", {"i": 0})
    ledger.append(iid, "PROVE", "oracle_verdict", "oracle:intent", {"i": 1})
    ledger.append(iid, "MEASURE", "prompt", "llm", {"i": 2})
    ledger.append(iid, "APPROVE", "approval", "human", {"i": 3})


def test_clean_chain_verifies(netops_table):
    _chain("i1")
    v = ledger.verify_ledger("i1")
    assert v["valid"] and v["length"] == 4 and v["first_break_seq"] is None


def test_seq_is_contiguous_and_head_tracks(netops_table):
    _chain("i1")
    entries = sorted(ddb.query_ledger("i1"), key=lambda e: int(e["seq"]))
    assert [int(e["seq"]) for e in entries] == [1, 2, 3, 4]
    head = ddb.table().get_item(Key={"pk": "INCIDENT#i1", "sk": "LEDGER_HEAD"})["Item"]
    assert int(head["seq"]) == 4 and head["head_hash"] == entries[-1]["entry_hash"]


def test_altered_payload_breaks_chain(netops_table):
    _chain("i1")
    # tamper: rewrite entry seq 2's payload directly in the table
    ddb.table().update_item(
        Key={"pk": "INCIDENT#i1", "sk": ledger_sk("i1", 2)},
        UpdateExpression="SET payload = :p",
        ExpressionAttributeValues={":p": '{"i": 999}'})
    v = ledger.verify_ledger("i1")
    assert not v["valid"] and v["first_break_seq"] == 2


def test_deleted_entry_breaks_chain(netops_table):
    _chain("i1")
    ddb.table().delete_item(Key={"pk": "INCIDENT#i1", "sk": ledger_sk("i1", 3)})
    v = ledger.verify_ledger("i1")
    assert not v["valid"] and v["first_break_seq"] == 3  # seq jumps 2 -> 4


def test_inserted_forged_entry_breaks_chain(netops_table):
    _chain("i1")
    # forge an entry with a plausible seq but no valid prev/entry hash
    ddb.table().put_item(Item={"pk": "INCIDENT#i1", "sk": "LEDGER#2026-07-24T00:00:00.000Z#000000009",
                               "seq": 9, "stage": "EXECUTE", "kind": "tool_call", "actor": "attacker",
                               "payload": "{}", "truncated": False,
                               "prev_hash": "x" * 64, "entry_hash": "y" * 64, "ts": "2026-07-24T00:00:00.000Z"})
    v = ledger.verify_ledger("i1")
    assert not v["valid"]


def test_empty_incident_is_not_valid(netops_table):
    assert not ledger.verify_ledger("nope")["valid"]



def test_every_ledger_read_is_strongly_consistent(netops_table, monkeypatch):
    """Query/GetItem default to eventually-consistent reads. A stale read here manufactures a
    false tamper alarm -- and governance anchors that wrong head out-of-band, permanently.
    Every read that feeds the hash chain must pin ConsistentRead=True."""
    seen = []

    class Spy:
        def __init__(self, t):
            self._t = t

        def get_item(self, **kw):
            seen.append(("get_item", kw.get("ConsistentRead")))
            return self._t.get_item(**kw)

        def query(self, **kw):
            seen.append(("query", kw.get("ConsistentRead")))
            return self._t.query(**kw)

        def __getattr__(self, name):
            return getattr(self._t, name)

    real = ddb.table
    monkeypatch.setattr(ddb, "table", lambda: Spy(real()))
    monkeypatch.setattr(ledger, "table", lambda: Spy(real()))

    ledger.append("c9", "DETECT", "event", "system", {"x": 1})
    assert ledger.verify_ledger("c9")["valid"]
    assert seen, "spy never engaged"
    assert all(cr is True for _, cr in seen), seen
