"""Cryptographically verify an incident's decision ledger. Read-only.

  python scripts/verify_ledger.py <incident_id>
Exit 0 = chain intact; exit 1 = tampering detected (with the first broken seq);
exit 2 = no such incident (a typo'd id must never read as a tampering report).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import ledger


def _use_deployed_table() -> str:
    """Point shared.ddb at the deployed table. These scripts are run standalone by an auditor
    who hasn't set TABLE_NAME, so resolve it from the stack outputs (like the other scripts)."""
    import boto3
    stack = os.environ.get("PLATFORM_STACK", "netops-platform")
    outs = boto3.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]
    name = {o["OutputKey"]: o["OutputValue"] for o in outs}["TableName"]
    os.environ["TABLE_NAME"] = name
    return name

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_ledger.py <incident_id>")
    _use_deployed_table()
    r = ledger.verify_ledger(sys.argv[1])
    if r["length"] == 0:
        print(f"NOT FOUND — no ledger entries for incident {sys.argv[1]!r}")
        sys.exit(2)
    if r["valid"]:
        print(f"VALID — {r['length']} entries, head {r['head'][:16]}...")
        sys.exit(0)
    print(f"BROKEN — chain fails at seq {r['first_break_seq']} (length {r['length']})")
    sys.exit(1)
