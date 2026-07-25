"""Eval harness: seed every labeled fault, let the closed loop run, auto-approve,
score the outcome. Release gate consumes the printed summary (release_model.ps1).

  python scripts/evaluate.py                # all 9 classes
  python scripts/evaluate.py --only route-deleted
Scores per case: diagnosed (LLM class == label), remediated (RESOLVED),
mttr_s (seed -> resolved), cost (RA analyses x $0.10).
"""
import argparse
import json
import os
import sys
import time
import uuid

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import chaos

from shared import baseline as base_mod

CASE_TIMEOUT_S = 1200
# must match shared.status.TERMINAL -- a missing member makes a correct outcome poll for 20 min
TERMINAL = {"RESOLVED", "VERIFICATION_LIMITED", "FAILED", "GATE_BLOCKED", "EXPIRED", "REJECTED",
            "CANCELLED", "FALSE_POSITIVE"}


def clean_check(table) -> None:
    cfg = table.get_item(Key={"pk": "CONFIG", "sk": "BASELINE"})["Item"]
    diff = base_mod.diff(json.loads(cfg["snapshot"]),
                         base_mod.snapshot(json.loads(cfg["inventory"])))
    if diff:
        raise SystemExit(f"lab not at baseline before case ({len(diff)} diffs) - run chaos.py --restore")


def incidents_since(table, iso: str) -> list[dict]:
    resp = table.query(IndexName="GSI1",
                       KeyConditionExpression="gsi1pk = :p AND gsi1sk >= :t",
                       ExpressionAttributeValues={":p": "INC", ":t": iso})
    return resp.get("Items", [])


def run_case(table, sfn, fault: str, lab: dict) -> dict:
    """Seed one labeled fault, drive it to a terminal state, score it. ALWAYS restores the lab
    (finally) -- an exception mid-case must never leave the network broken for the next case."""
    clean_check(table)
    seed_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.time()
    try:
        chaos.seed(fault, lab)
        print(f"  seeded {fault}")
        incident = _drive(table, sfn, seed_iso, t0)

        if incident is None or incident["status"] not in TERMINAL:
            return {"fault": fault, "diagnosed": False, "remediated": False,
                    "mttr_s": None, "ra": 0, "note": "timeout"}

        incident = table.get_item(Key={"pk": incident["pk"], "sk": "META"})["Item"]
        remediated = incident["status"] in ("RESOLVED", "VERIFICATION_LIMITED")
        return {"fault": fault,
                "diagnosed": incident.get("llm_fault_class") == fault,
                "det_correct": incident.get("fault_class") == fault,
                "remediated": remediated,
                "mttr_s": int(time.time() - t0) if remediated else None,
                "ra": int(incident.get("ra_analyses_used", 0)),
                "note": incident["status"]}
    finally:
        chaos.restore()  # no-op when already at baseline


def _drive(table, sfn, seed_iso: str, t0: float):
    """Poll until terminal, completing approval tokens as they appear.
    Tier-aware: LOW auto-executes (AUTO_EXEC_PENDING -> just wait), MEDIUM takes one approval,
    HIGH takes two (a distinct token each). The harness completes tokens DIRECTLY, so it
    validates the loop, not the API's SoD/plan-integrity controls (those are unit-tested)."""
    incident, last_token = None, None
    while time.time() - t0 < CASE_TIMEOUT_S:
        items = incidents_since(table, seed_iso)
        if items:
            incident = max(items, key=lambda i: i["gsi1sk"])
            status, token = incident["status"], incident.get("task_token")
            if status in ("AWAITING_APPROVAL", "AWAITING_SECOND_APPROVAL") and token and token != last_token:
                try:
                    sfn.send_task_success(taskToken=token, output=json.dumps({"approved_by": "eval-harness"}))
                    print(f"  auto-approved ({status})")
                except ClientError as e:
                    # a token the workflow already resolved: expected under GSI eventual
                    # consistency, not a failure
                    print(f"  token already resolved ({e.response['Error']['Code']})")
                last_token = token
                time.sleep(5)
                continue
            if status in TERMINAL:
                break
        time.sleep(10)
    return incident


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    args = ap.parse_args()
    faults = [args.only] if args.only else chaos.FAULTS

    table = chaos._table()
    sfn = boto3.client("stepfunctions")
    lab = chaos.outputs()
    model_id = os.environ.get("MODEL_ID", "us.amazon.nova-micro-v1:0")

    results = []
    for fault in faults:
        print(f"case {fault}")
        r = run_case(table, sfn, fault, lab)
        results.append(r)
        print(f"  -> diagnosed={r['diagnosed']} remediated={r['remediated']} "
              f"mttr={r['mttr_s']}s ra={r['ra']} ({r['note']})")
        time.sleep(20)  # let correlation windows close between cases

    total = len(results)
    diagnosed = sum(r["diagnosed"] for r in results)
    det = sum(r.get("det_correct", False) for r in results)
    remediated = sum(r["remediated"] for r in results)
    mttrs = [r["mttr_s"] for r in results if r["mttr_s"]]
    mean_mttr = int(sum(mttrs) / len(mttrs)) if mttrs else 0
    ra_total = sum(r["ra"] for r in results)
    cost = round(ra_total * 0.10, 2)

    run_id = time.strftime("%Y%m%d-%H%M") + "-" + uuid.uuid4().hex[:4]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    table.put_item(Item={"pk": f"EVAL#{run_id}", "sk": "META", "gsi1pk": "EVAL",
                         "gsi1sk": now, "model_id": model_id, "total": total,
                         "diagnosed": diagnosed, "det_correct": det,
                         "remediated": remediated, "mean_mttr_s": mean_mttr,
                         "cost_usd": str(cost)})
    for r in results:
        table.put_item(Item={"pk": f"EVAL#{run_id}", "sk": f"CASE#{r['fault']}",
                             **{k: (str(v) if v is None else v) for k, v in r.items()}})

    print(f"\n| {now} | {model_id} | {det}/{total} | {diagnosed}/{total} | "
          f"{remediated}/{total} | {mean_mttr}s | ${cost} |")
    print(f"RESULT diagnosed={diagnosed}/{total} remediated={remediated}/{total} mean_mttr={mean_mttr}")


if __name__ == "__main__":
    main()
