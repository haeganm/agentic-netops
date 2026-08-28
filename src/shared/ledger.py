"""Append-only, TAMPER-EVIDENT incident ledger (ADR 0014).

Every stage transition, prompt, tool call, oracle verdict, gate result, approval, and outcome
is one entry in a per-incident hash chain: each entry's hash covers the previous head hash, so
any insertion, alteration, or deletion of an entry breaks every downstream hash. verify_ledger()
replays the chain and reports the first broken sequence number.

On every terminal outcome, functions/governance:anchor_ledger records the head on the incident
AND publishes it out-of-band via SNS -- because a role with table write access could otherwise
rewrite the entries and the LEDGER_HEAD item consistently. The emailed copy is what makes that
detectable.
"""
import hashlib
import json
import time

from botocore.exceptions import ClientError

from shared.ddb import query_by_prefix, table

MAX_PAYLOAD = 8192
GENESIS = "0" * 64

STAGES = ("DETECT", "PROVE", "MEASURE", "GENERATE-REPAIR", "APPROVE", "EXECUTE", "VERIFY")
KINDS = ("event", "prompt", "tool_call", "oracle_verdict", "gate", "approval", "outcome")


def _head_key(incident_id: str) -> dict:
    return {"pk": f"INCIDENT#{incident_id}", "sk": "LEDGER_HEAD"}


def _entry_hash(prev_head: str, entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_head + canonical).encode()).hexdigest()


def append(incident_id: str, stage: str, kind: str, actor: str, payload: dict) -> None:
    """Add one chained entry. The per-incident HEAD is advanced under an optimistic lock on
    its seq (the serialization point: concurrent appends to the same incident can't both claim
    the same seq -- the loser retries against the new head), then the entry is written. A crash
    between the two writes leaves a head/entry mismatch that verify_ledger() flags -- benign and
    detectable, never a silent gap (ADR 0014)."""
    assert stage in STAGES and kind in KINDS
    t = table()
    body = json.dumps(payload, default=str)
    core = {
        "stage": stage, "kind": kind, "actor": actor,
        "payload": body[:MAX_PAYLOAD], "truncated": len(body) > MAX_PAYLOAD,
    }

    # ponytail: single-item optimistic lock, 8 immediate retries. Fine at lab volume;
    # switch to per-incident write sharding only if append throughput ever bottlenecks.
    for _ in range(8):
        # ConsistentRead: a stale head read guarantees a CAS failure (the write conditions are
        # always strongly consistent), burning retries against a replica, not real contention.
        head = t.get_item(Key=_head_key(incident_id), ConsistentRead=True).get("Item")
        prev_seq = int(head["seq"]) if head else 0
        prev_head = head["head_hash"] if head else GENESIS
        seq = prev_seq + 1

        ts = time.time()
        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int(ts % 1 * 1000):03d}Z"
        # the hashed content -- everything an auditor would compare, nothing volatile beyond ts
        signed = {**core, "seq": seq, "ts": iso}
        eh = _entry_hash(prev_head, signed)

        try:
            if head is None:
                t.update_item(
                    Key=_head_key(incident_id),
                    UpdateExpression="SET seq = :s, head_hash = :h",
                    ConditionExpression="attribute_not_exists(pk)",
                    ExpressionAttributeValues={":s": seq, ":h": eh})
            else:
                t.update_item(
                    Key=_head_key(incident_id),
                    UpdateExpression="SET seq = :s, head_hash = :h",
                    ConditionExpression="seq = :prev",
                    ExpressionAttributeValues={":s": seq, ":h": eh, ":prev": prev_seq})
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                continue  # another append advanced the head; re-read and retry
            raise

        t.put_item(Item={
            "pk": f"INCIDENT#{incident_id}", "sk": f"LEDGER#{iso}#{seq:09d}",
            **core, "seq": seq, "ts": iso, "prev_hash": prev_head, "entry_hash": eh,
        })
        return
    raise RuntimeError(f"ledger append contention on {incident_id} after 8 retries")


def verify_ledger(incident_id: str) -> dict:
    """Replay genesis -> head. Returns {valid, length, head, first_break_seq}. Any alteration,
    insertion, or deletion of an entry breaks a downstream hash -> valid=False at that seq."""
    # ConsistentRead on BOTH reads: governance anchors this result out-of-band immediately
    # after the last append -- an eventually-consistent read here can miss the tail entry,
    # report a false break, and permanently anchor the wrong head.
    entries = sorted(query_by_prefix(f"INCIDENT#{incident_id}", "LEDGER#", ConsistentRead=True),
                     key=lambda e: int(e["seq"]))
    head = table().get_item(Key=_head_key(incident_id), ConsistentRead=True).get("Item")

    running = GENESIS
    for i, e in enumerate(entries, start=1):
        if int(e["seq"]) != i:
            return {"valid": False, "length": len(entries), "head": head and head.get("head_hash"),
                    "first_break_seq": i}
        signed = {"stage": e["stage"], "kind": e["kind"], "actor": e["actor"],
                  "payload": e["payload"], "truncated": e["truncated"],
                  "seq": int(e["seq"]), "ts": e["ts"]}
        recomputed = _entry_hash(running, signed)
        if e.get("prev_hash") != running or e.get("entry_hash") != recomputed:
            return {"valid": False, "length": len(entries), "head": head and head.get("head_hash"),
                    "first_break_seq": int(e["seq"])}
        running = recomputed

    head_ok = head is not None and head.get("head_hash") == running and int(head["seq"]) == len(entries)
    return {"valid": bool(entries) and head_ok, "length": len(entries),
            "head": running if entries else None,
            "first_break_seq": None if head_ok else len(entries) + 1}
