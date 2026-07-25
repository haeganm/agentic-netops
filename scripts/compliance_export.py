"""Auditor-ready compliance export for an incident (markdown + JSON). Read-only.

  python scripts/compliance_export.py <incident_id> [--json]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import evidence


def _use_deployed_table() -> str:
    """Point shared.ddb at the deployed table. These scripts are run standalone by an auditor
    who hasn't set TABLE_NAME, so resolve it from the stack outputs (like the other scripts)."""
    import boto3
    stack = os.environ.get("PLATFORM_STACK", "netops-platform")
    outs = boto3.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]
    name = {o["OutputKey"]: o["OutputValue"] for o in outs}["TableName"]
    os.environ["TABLE_NAME"] = name
    # the session-policy recompute needs the account id (a Lambda env var in the deployed stack)
    os.environ.setdefault("ACCOUNT_ID", boto3.client("sts").get_caller_identity()["Account"])
    return name


def _md(r: dict) -> str:
    c = r["controls"]
    chain = c["tamper_evident"]
    ca, lp, vf, wp, ho = (c["change_authorized"], c["least_privilege"], c["verified"],
                          c["within_policy"], c["human_oversight"])
    # ASCII only: this prints to a Windows console (cp1252) as often as to a file.
    lines = [
        f"# Compliance evidence - incident {r['incident_id']}",
        f"- status: **{r['status']}** | fault: {r['fault_class']} | MTTR: {r['mttr_s']}s",
        f"- ledger entries: {r['ledger_entries']}",
        "",
        "## Control assertions",
        (f"**Change authorized** - tier `{ca['tier']}`; authorized by {ca['authorized_by']}; "
         f"approvals: {ca['approvals'] or 'none'}"),
        (f"**Least privilege** - scoped STS session policy recomputed: "
         f"{lp['remediation_via_scoped_sts']}; applied ops: {lp['applied_operations']}"),
        (f"**Verified** - intent {vf['intent']}; impact reachability "
         f"{vf['impact_reachable'] or 'n/a for this fault class'}; data-plane {vf['data_plane']}; "
         f"scope: {vf['verification_scope']}"),
        f"**Within policy** - gate {wp['gate_verdict']} (policy {wp['policy_version']}), violations: {wp['violations']}",
        (f"**Human oversight** - drift caused by `{ho['drift_actor']}`; "
         f"approvers: {ho['approvers'] or 'none (auto-executed under a veto window)'}; "
         f"SoD evaluated: {ho['sod_enforced']}; two-party: {ho['two_party']}"),
        (f"**Tamper-evident** - ledger chain **{'VALID' if chain['valid'] else 'BROKEN'}** "
         f"(len {chain['length']}, head `{str(chain['head'] or '')[:16]}...`)"),
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("incident_id")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    _use_deployed_table()
    report = evidence.build_report(args.incident_id)
    if report is None:
        raise SystemExit(f"no such incident {args.incident_id}")
    print(json.dumps(report, indent=2, default=str) if args.json else _md(report))
