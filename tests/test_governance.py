"""Governance plumbing: task-token persistence (every approval wait depends on it) and the
tamper-evidence anchor. Neither had any test despite mediating all human decisions."""
import json

from functions.governance import handler
from shared import ddb, ledger, status


def test_store_token_sets_wait_status_and_no_deadline(netops_table):
    ddb.create_incident("g1", {"status": status.PROVING, "gsi1sk": "2026"})
    handler.lambda_handler({"op": "store_token", "incident_id": "g1", "token": "TOK",
                            "wait_status": status.AWAITING_APPROVAL, "gate": "PASS"}, None)
    meta = ddb.get_incident("g1")
    assert meta["task_token"] == "TOK"
    assert meta["status"] == status.AWAITING_APPROVAL
    assert "veto_deadline" not in meta  # only the veto window has a deadline


def test_store_token_veto_deadline_anchors_to_state_entry_time(netops_table):
    """The countdown the console shows must derive from the STATE's EnteredTime, not this
    Lambda's clock -- otherwise the advertised window outlives the real TimeoutSeconds and
    CANCEL 409s while remediation is already executing."""
    ddb.create_incident("g2", {"status": status.PROVING, "gsi1sk": "2026"})
    handler.lambda_handler({"op": "store_token", "incident_id": "g2", "token": "TOK",
                            "wait_status": status.AUTO_EXEC_PENDING, "deadline_seconds": 60,
                            "entered_at": "2026-07-24T22:26:50.123Z"}, None)
    meta = ddb.get_incident("g2")
    assert meta["status"] == status.AUTO_EXEC_PENDING
    assert meta["veto_deadline"] == "2026-07-24T22:27:50Z"  # entry time + exactly 60s


def test_store_token_falls_back_when_entered_at_is_unusable(netops_table):
    ddb.create_incident("g3", {"status": status.PROVING, "gsi1sk": "2026"})
    handler.lambda_handler({"op": "store_token", "incident_id": "g3", "token": "T",
                            "wait_status": status.AUTO_EXEC_PENDING, "deadline_seconds": 60,
                            "entered_at": "not-a-timestamp"}, None)
    assert ddb.get_incident("g3")["veto_deadline"]  # present, derived from wall clock


def test_anchor_records_chain_head_and_mttr(netops_table):
    ddb.create_incident("g4", {"status": status.RESOLVED, "gsi1sk": "2026",
                               "created_at": "2026-07-24T22:25:08Z",
                               "resolved_at": "2026-07-24T22:28:19.500Z"})
    ledger.append("g4", "DETECT", "event", "system", {"a": 1})
    ledger.append("g4", "VERIFY", "oracle_verdict", "oracle:intent", {"diff_count": 0})

    out = handler.lambda_handler({"op": "anchor_ledger", "incident_id": "g4"}, None)
    chain = ledger.verify_ledger("g4")
    meta = ddb.get_incident("g4")
    assert out["chain_head"] == chain["head"]
    assert meta["chain_head"] == chain["head"] and int(meta["chain_len"]) == 2
    assert int(meta["mttr_s"]) == 191  # 22:28:19 - 22:25:08


def test_anchor_is_honest_about_a_broken_chain(netops_table):
    """Anchoring must report what it finds, not assert validity."""
    ddb.create_incident("g5", {"status": status.FAILED, "gsi1sk": "2026"})
    ledger.append("g5", "DETECT", "event", "system", {"a": 1})
    ledger.append("g5", "EXECUTE", "tool_call", "system", {"a": 2})
    from conftest import ledger_sk
    ddb.table().update_item(Key={"pk": "INCIDENT#g5", "sk": ledger_sk("g5", 2)},
                            UpdateExpression="SET actor = :a",
                            ExpressionAttributeValues={":a": "attacker"})
    assert handler.lambda_handler({"op": "anchor_ledger", "incident_id": "g5"}, None)["valid"] is False


def test_unknown_op_raises(netops_table):
    import pytest
    with pytest.raises(ValueError, match="unknown op"):
        handler.lambda_handler({"op": "nope", "incident_id": "x"}, None)


def test_anchor_on_incident_with_no_ledger(netops_table):
    """A gate-blocked incident may terminate with almost no history; anchoring must not crash."""
    ddb.create_incident("g6", {"status": status.GATE_BLOCKED, "gsi1sk": "2026"})
    out = handler.lambda_handler({"op": "anchor_ledger", "incident_id": "g6"}, None)
    assert out["anchored"] is True
    assert json.loads(json.dumps(out))  # serializable for the SFN result path
