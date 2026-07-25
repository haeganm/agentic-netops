"""DynamoDB access. Single table, single org.

Key map (authoritative -- keep in step with the code below):

  pk=INCIDENT#{id}  sk=META                  the incident record
                    sk=LEDGER#{iso}#{seq}    tamper-evident decision ledger (ADR 0014)
                    sk=LEDGER_HEAD           that chain's {seq, head_hash}
  pk=CONFIG         sk=BASELINE              declared intent: snapshot + inventory (ADR 0003)
                    sk=MODE                  normal | maintenance (detector suppression)
                    sk=AUTONOMY              {mode: normal|manual} kill-switch (ADR 0011)
                    sk=APPROVERS             {map: {cognito_email: iam_arn}} for SoD (ADR 0013)
  pk=LIMITS#RA      sk=COUNTER               Reachability Analyzer budget {used, cap} (ADR 0005)
  pk=EVAL#{run}     sk=META | CASE#{fault_class}

CONFIG#* is admin/seed-writable only: every runtime role's write grant is IAM-scoped to
INCIDENT#* (ADR 0010), and LIMITS#RA lives in its OWN partition precisely so the one runtime
writer (the oracles function) can be scoped to it alone.

GSI1 (gsi1pk=INC, gsi1sk=created_iso) lists incidents by recency; gsi1pk=EVAL lists eval runs.
DDB_ENDPOINT env var points at DynamoDB Local in dev.
"""
import os

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


def table():
    kwargs = {}
    if os.environ.get("DDB_ENDPOINT"):
        kwargs["endpoint_url"] = os.environ["DDB_ENDPOINT"]
    return boto3.resource("dynamodb", **kwargs).Table(os.environ.get("TABLE_NAME", "netops"))


# ---- incidents ----
def incident_key(incident_id: str) -> dict:
    return {"pk": f"INCIDENT#{incident_id}", "sk": "META"}


def create_incident(incident_id: str, item: dict) -> bool:
    """Conditional put = idempotency; False if the incident already exists."""
    try:
        table().put_item(
            Item={**incident_key(incident_id), "gsi1pk": "INC", **item},
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def get_incident(incident_id: str) -> dict | None:
    return table().get_item(Key=incident_key(incident_id)).get("Item")


def update_incident(incident_id: str, **fields) -> None:
    # '#f0 = :v0' aliases every name: status/tokens/plan are DDB reserved words.
    names = {f"#f{i}": k for i, k in enumerate(fields)}
    values = {f":v{i}": v for i, v in enumerate(fields.values())}
    expr = ", ".join(f"#f{i} = :v{i}" for i in range(len(fields)))
    table().update_item(
        Key=incident_key(incident_id),
        UpdateExpression=f"SET {expr}",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def claim_first_approver(incident_id: str, actor: str) -> bool:
    """Atomically claim the first-approver slot. False = already claimed by someone else,
    which is what makes two-party control unforgeable under concurrent approvals (ADR 0013)."""
    try:
        table().update_item(
            Key=incident_key(incident_id),
            UpdateExpression="SET first_approver = :a",
            ConditionExpression="attribute_not_exists(first_approver)",
            ExpressionAttributeValues={":a": actor},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def list_incidents(limit: int = 50) -> list[dict]:
    resp = table().query(
        IndexName="GSI1",
        KeyConditionExpression=Key("gsi1pk").eq("INC"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def query_ledger(incident_id: str) -> list[dict]:
    return query_by_prefix(f"INCIDENT#{incident_id}", "LEDGER#")


def list_evals(limit: int = 20) -> list[dict]:
    resp = table().query(
        IndexName="GSI1",
        KeyConditionExpression=Key("gsi1pk").eq("EVAL"),
        ScanIndexForward=False, Limit=limit,
    )
    return resp.get("Items", [])


# ---- config (admin/seed-writable only; runtime roles may READ but not write, enforced by IAM) ----
def config_key(name: str) -> dict:
    return {"pk": "CONFIG", "sk": name}


def get_config(name: str) -> dict | None:
    return table().get_item(Key=config_key(name)).get("Item")


def put_config(name: str, item: dict) -> None:
    table().put_item(Item={**config_key(name), **item})


# ---- RA budget counter (its OWN partition so the one runtime writer -- the oracles
# function -- can be IAM-scoped to it, keeping CONFIG#* writable by no runtime role) ----
RA_BUDGET_KEY = {"pk": "LIMITS#RA", "sk": "COUNTER"}


def get_ra_budget() -> dict | None:
    return table().get_item(Key=RA_BUDGET_KEY).get("Item")


def put_ra_budget(used: int, cap: int) -> None:
    table().put_item(Item={**RA_BUDGET_KEY, "used": used, "cap": cap})


def consume_ra_budget() -> bool:
    """Atomically claim one Reachability Analyzer analysis against the hard cap.
    Fail-closed: missing counter item (or used >= cap) -> False, no analysis runs."""
    try:
        table().update_item(
            Key=RA_BUDGET_KEY,
            UpdateExpression="ADD #u :one",
            ConditionExpression="#u < cap",
            ExpressionAttributeNames={"#u": "used"},
            ExpressionAttributeValues={":one": 1},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


# ---- shared paginated query on an sk prefix (public: ledger.verify_ledger uses it) ----
def query_by_prefix(pk: str, sk_prefix: str, **kwargs) -> list[dict]:
    t = table()
    cond = Key("pk").eq(pk) & Key("sk").begins_with(sk_prefix)
    items, resp = [], t.query(KeyConditionExpression=cond, **kwargs)
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp = t.query(KeyConditionExpression=cond, ExclusiveStartKey=resp["LastEvaluatedKey"], **kwargs)
        items.extend(resp.get("Items", []))
    return items
