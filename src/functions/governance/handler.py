"""Governance plumbing for the loop -- deliberately NOT an oracle, and deliberately a separate
Lambda from the measurement functions so the code path that mediates every human approval does
not carry Reachability-Analyzer read permissions.

Ops:
  store_token    -- persist a Step Functions callback token + the wait status (APPROVE stage).
                    Serves all three waits: single approval, second approval, and the LOW-tier
                    veto window.
  anchor_ledger  -- on a terminal outcome, publish the tamper-evident chain head OUT OF BAND
                    (SNS) and record it on the incident. Out-of-band matters: a role with table
                    write access could rewrite both the entries and the LEDGER_HEAD item
                    consistently, so an emailed copy of the head is what makes after-the-fact
                    tampering detectable (ADR 0014).
"""
import calendar
import contextlib
import os
import time

from shared import ddb, evidence, ledger
from shared import status as st
from shared.log import log


def lambda_handler(event, context):
    op = event["op"]
    iid = event["incident_id"]

    if op == "store_token":
        wait_status = event.get("wait_status", st.AWAITING_APPROVAL)
        fields = {"task_token": event["token"], "status": wait_status}
        if event.get("deadline_seconds"):
            # Anchor the countdown to the STATE's entry time, not this Lambda's clock: the SFN
            # TimeoutSeconds starts when the state is entered, so deriving it from time.time()
            # here (after invoke + cold start) advertised a window that outlived the real one.
            fields["veto_deadline"] = _deadline(event.get("entered_at"),
                                                int(event["deadline_seconds"]))
        ddb.update_incident(iid, **fields)
        ledger.append(iid, "APPROVE", "approval", "system",
                      {"state": "awaiting", "wait_status": wait_status, "gate": event.get("gate")})
        log("awaiting_decision", incident_id=iid, wait_status=wait_status)
        return {"stored": True}

    if op == "anchor_ledger":
        chain = ledger.verify_ledger(iid)
        meta = ddb.get_incident(iid) or {}
        mttr = evidence.mttr_seconds(meta)
        fields = {"chain_head": chain.get("head") or "", "chain_len": chain.get("length", 0)}
        if mttr is not None:
            fields["mttr_s"] = mttr
        ddb.update_incident(iid, **fields)

        topic = os.environ.get("ALERT_TOPIC_ARN")
        if topic:
            import boto3

            boto3.client("sns").publish(
                TopicArn=topic,
                Subject=f"netops ledger anchor {iid}",
                Message=(f"incident: {iid}\nstatus: {meta.get('status')}\n"
                         f"chain length: {chain.get('length')}\n"
                         f"chain head: {chain.get('head')}\n"
                         f"chain valid at anchor time: {chain.get('valid')}\n\n"
                         "Retain this message: it is the out-of-band copy of the decision-ledger "
                         "hash chain head. Re-run scripts/verify_ledger.py and compare."),
            )
        log("ledger_anchored", incident_id=iid, chain_len=chain.get("length"),
            valid=chain.get("valid"), mttr_s=mttr)
        return {"anchored": True, "chain_head": chain.get("head"), "valid": chain.get("valid")}

    raise ValueError(f"unknown op {op}")


def _deadline(entered_at: str | None, seconds: int) -> str:
    """Veto deadline = the SFN state's EnteredTime + the window, so the console countdown
    matches the real TimeoutSeconds. Falls back to this Lambda's clock if unavailable."""
    base = time.time()
    if entered_at:
        # SFN sends ISO-8601 with millis, e.g. 2026-07-24T22:26:50.123Z
        with contextlib.suppress(ValueError):
            base = calendar.timegm(time.strptime(entered_at[:19] + "Z", "%Y-%m-%dT%H:%M:%SZ"))
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base + seconds))
