"""MEASURE-stage oracle operations, dispatched by `op`. Every op here consults an oracle and
ledgers its verdict; governance plumbing (task tokens, ledger anchoring) deliberately lives in
functions/governance so this function's broader read permissions stay off the approval path.

  drift_start / drift_poll  -- CloudFormation drift detection (intent, advisory)
  ra_start / ra_poll        -- Reachability Analyzer (impact; budget-guarded, ADR 0005)
  probe_record              -- ledger the in-VPC probe's verdict (the probe itself
                               cannot reach AWS APIs by design)
"""
import json
import os

import boto3

from shared import ddb, ledger
from shared.log import log

# ponytail: fixed poll ceiling (12 x 20s = 4min). An analysis still running at the ceiling is
# reported inconclusive, never "unreachable"; make it adaptive only if RA gets slower.
MAX_POLLS = 12


def lambda_handler(event, context):
    op = event["op"]
    iid = event["incident_id"]
    stage = event.get("stage", "MEASURE")

    if op == "drift_start":
        cfn = boto3.client("cloudformation")
        did = cfn.detect_stack_drift(StackName=os.environ["LAB_STACK"])["StackDriftDetectionId"]
        return {"id": did, "polls": 0, "done": False}

    if op == "drift_poll":
        cfn = boto3.client("cloudformation")
        resp = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=event["id"])
        polls = event.get("polls", 0) + 1
        done = resp["DetectionStatus"] != "DETECTION_IN_PROGRESS" or polls >= MAX_POLLS
        if done:
            verdict = {"status": resp["DetectionStatus"],
                       "stack_drift": resp.get("StackDriftStatus", "UNKNOWN"),
                       "drifted_resources": resp.get("DriftedStackResourceCount", 0)}
            ledger.append(iid, stage, "oracle_verdict", "oracle:intent-cfn", verdict)
            log("drift_done", incident_id=iid, **verdict)
        return {"id": event["id"], "polls": polls, "done": done}

    if op == "ra_start":
        path_key = event["path_key"]
        cfg = ddb.get_config("BASELINE")
        path_id = json.loads(cfg["inventory"])["paths"][path_key]
        if not ddb.consume_ra_budget():
            ledger.append(iid, stage, "oracle_verdict", "oracle:impact",
                          {"verdict": "skipped-budget", "path": path_key})
            ddb.update_incident(iid, verification="LIMITED")
            log("ra_skipped_budget", incident_id=iid)
            return {"started": False, "done": True, "polls": 0}
        ec2 = boto3.client("ec2")
        aid = ec2.start_network_insights_analysis(NetworkInsightsPathId=path_id)[
            "NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]
        log("ra_started", incident_id=iid, analysis_id=aid, path=path_key)
        return {"started": True, "id": aid, "path_key": path_key, "polls": 0, "done": False}

    if op == "ra_poll":
        ec2 = boto3.client("ec2")
        a = ec2.describe_network_insights_analyses(
            NetworkInsightsAnalysisIds=[event["id"]])["NetworkInsightsAnalyses"][0]
        polls = event.get("polls", 0) + 1
        exhausted = polls >= MAX_POLLS and a["Status"] == "running"
        done = a["Status"] != "running" or exhausted
        result = {"started": True, "id": event["id"], "path_key": event.get("path_key"),
                  "polls": polls, "done": done}
        if exhausted:
            # An analysis still running when we stop waiting has proven NOTHING. Reporting
            # reachable=false here would be a false negative that fails a correctly-remediated
            # incident -- and would be ledgered as evidence. Degrade like a budget skip instead.
            result["started"] = False
            ledger.append(iid, stage, "oracle_verdict", "oracle:impact",
                          {"verdict": "inconclusive-timeout", "path": event.get("path_key"),
                           "analysis_id": event["id"], "polls": polls})
            ddb.update_incident(iid, verification="LIMITED")
            log("ra_inconclusive", incident_id=iid, polls=polls)
        elif done:
            result["reachable"] = bool(a.get("NetworkPathFound", False))
            ledger.append(iid, stage, "oracle_verdict", "oracle:impact",
                          {"verdict": a["Status"], "reachable": result["reachable"],
                           "path": event.get("path_key"), "analysis_id": event["id"]})
            ddb.table().update_item(
                Key=ddb.incident_key(iid),
                UpdateExpression="ADD ra_analyses_used :one",
                ExpressionAttributeValues={":one": 1})
            log("ra_done", incident_id=iid, reachable=result["reachable"])
        return result

    if op == "probe_record":
        verdict = event["verdict"]
        ledger.append(iid, stage, "oracle_verdict", "oracle:dataplane", verdict)
        log("probe_recorded", incident_id=iid, dns=verdict.get("dns"), tcp=verdict.get("tcp"))
        return {"recorded": True, "dns": verdict.get("dns"), "tcp": verdict.get("tcp")}

    raise ValueError(f"unknown op {op}")
