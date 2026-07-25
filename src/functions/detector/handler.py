"""DETECT: SQS batches of EventBridge-wrapped CloudTrail management events.

Filters to events touching lab-inventory resources, drops self-inflicted changes
(remediation session, maintenance mode), correlates bursts into one incident, and
starts the closed-loop workflow exactly once per incident (conditional put).
"""
import hashlib
import json
import os
import re
import time

from shared import ddb, ledger, status
from shared.log import log

RESOURCE_ID_RE = re.compile(r"\b(?:sg|rtb|acl|eni|vpc|subnet|igw|rtbassoc|aclassoc)-[0-9a-f]+\b")
CORRELATION_WINDOW_S = 600
# Only PRE-PROVE incidents coalesce a burst. Once PROVE has snapshotted, later drift is
# genuinely new and must get its own incident (else a second fault is silently absorbed).
CORRELATABLE_STATUS = status.DETECTED


def _remediation_prefix() -> str | None:
    """Exact assumed-role ARN prefix of the RemediationRole, e.g.
    arn:aws:sts::123:assumed-role/RoleName/ -- so we skip only the platform's OWN
    remediation calls, never an attacker-chosen session name (never a bare substring)."""
    role_arn = os.environ.get("REMEDIATION_ROLE_ARN", "")  # arn:aws:iam::{acct}:role/{name}
    m = re.match(r"arn:aws:iam::(\d+):role/(.+)$", role_arn)
    if not m:
        return None
    account, name = m.group(1), m.group(2)
    return f"arn:aws:sts::{account}:assumed-role/{name}/"


def lambda_handler(event, context):
    mode_item = ddb.get_config("MODE") or {}
    maintenance = mode_item.get("mode") == "maintenance"
    inventory_item = ddb.get_config("BASELINE") or {}
    inventory_ids = set(RESOURCE_ID_RE.findall(inventory_item.get("inventory", "")))
    remediation_prefix = _remediation_prefix()

    failures = []
    for record in event.get("Records", []):
        try:
            _handle(record, inventory_ids, maintenance, remediation_prefix)
        except Exception as e:  # noqa: BLE001 - partial batch: retry only the failed message
            log("detector_error", error=str(e)[:500], message_id=record.get("messageId"))
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


def _handle(record: dict, inventory_ids: set, maintenance: bool, remediation_prefix: str | None) -> None:
    detail = json.loads(record["body"]).get("detail", {})
    event_name = detail.get("eventName", "")
    event_id = detail.get("eventID", "")
    actor_arn = str(detail.get("userIdentity", {}).get("arn", ""))

    if maintenance:
        log("detector_skip", reason="maintenance", event_name=event_name)
        return
    # exact identity match, not a substring: an attacker naming their session
    # "netops-remediation-x" no longer suppresses detection of their own changes.
    if remediation_prefix and actor_arn.startswith(remediation_prefix):
        log("detector_skip", reason="self", event_name=event_name)
        return

    touched = set(RESOURCE_ID_RE.findall(json.dumps(detail.get("requestParameters") or {})))
    lab_touched = sorted(touched & inventory_ids)
    if not lab_touched:
        log("detector_skip", reason="not-lab", event_name=event_name)
        return

    summary = {"event_name": event_name, "event_id": event_id, "actor": actor_arn[:200],
               "event_time": detail.get("eventTime"), "resources": lab_touched}

    open_incident = _correlate(lab_touched)
    if open_incident:
        iid = open_incident["pk"].split("#", 1)[1]
        ledger.append(iid, "DETECT", "event", "system", summary)
        log("detector_correlated", incident_id=iid, event_name=event_name)
        return

    iid = hashlib.sha1(event_id.encode()).hexdigest()[:12]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    created = ddb.create_incident(iid, {
        "status": status.DETECTED, "created_at": now, "gsi1sk": now,
        "resource_ids": lab_touched,
        "drift_actor": actor_arn[:200],  # who caused it -- for segregation of duties (ADR 0013)
    })
    if created:
        ledger.append(iid, "DETECT", "event", "system", summary)
    else:
        # A prior attempt created the row but may have died before StartExecution
        # (crash between the two writes). If it's still DETECTED, (re)start -- never
        # leave an incident stranded, which would black-hole future correlated events.
        existing = ddb.get_incident(iid) or {}
        if existing.get("status") != status.DETECTED:
            log("detector_duplicate", incident_id=iid)
            return
        log("detector_recovering_start", incident_id=iid)

    _start_workflow(iid, lab_touched)
    log("incident_created", incident_id=iid, event_name=event_name, resources=lab_touched)


def _start_workflow(iid: str, lab_touched: list) -> None:
    sm_arn = os.environ.get("STATE_MACHINE_ARN", "")
    if not sm_arn:
        return
    import boto3

    sfn = boto3.client("stepfunctions")
    try:
        sfn.start_execution(
            stateMachineArn=sm_arn, name=f"incident-{iid}",  # name = idempotency key
            input=json.dumps({"incident_id": iid, "resource_ids": lab_touched}),
        )
    except sfn.exceptions.ExecutionAlreadyExists:
        log("detector_execution_exists", incident_id=iid)  # already running -- fine


def _correlate(resource_ids: list) -> dict | None:
    # ponytail: linear scan of the 25 most recent incidents. Correct because correlation
    # only ever considers a 10-minute window; add a status GSI if incident rate grows.
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - CORRELATION_WINDOW_S))
    for item in ddb.list_incidents(limit=25):
        if item.get("status") == CORRELATABLE_STATUS and item.get("gsi1sk", "") >= cutoff \
                and set(resource_ids) & set(item.get("resource_ids", [])):
            return item
    return None
