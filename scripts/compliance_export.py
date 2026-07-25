"""Auditor-ready compliance export for an incident (markdown + JSON). Read-only.

  python scripts/compliance_export.py <incident_id> [--json]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import evidence


def _md(r: dict) -> str:
    c = r["controls"]
    chain = c["tamper_evident"]
    ca, lp, vf, wp, ho = (c["change_authorized"], c["least_privilege"], c["verified"],
                          c["within_policy"], c["human_oversight"])
    lines = [
        f"# Compliance evidence — incident {r['incident_id']}",
        f"- status: **{r['status']}**  ·  fault: {r['fault_class']}  ·  MTTR: {r['mttr_s']}s",
        f"- ledger entries: {r['ledger_entries']}",
        "",
        "## Control assertions",
        (f"**Change authorized** — tier `{ca['tier']}`; approvals: "
         f"{ca['approvals'] or 'auto (LOW-tier veto window)'}"),
        f"**Least privilege** — per-incident scoped STS session policy; applied ops: {lp['applied_operations']}",
        f"**Verified** — intent re-diff + impact reachability {vf['impact_reachable']} + data-plane {vf['data_plane']}",
        f"**Within policy** — gate {wp['gate_verdict']} (policy {wp['policy_version']}), violations: {wp['violations']}",
        f"**Human oversight** — drift by `{ho['drift_actor']}`; approvers: {ho['approvers']}; SoD enforced",
        (f"**Tamper-evident** — ledger chain **{'VALID' if chain['valid'] else 'BROKEN'}** "
         f"(len {chain['length']}, head `{str(chain['head'] or '')[:16]}...`)"),
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("incident_id")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = evidence.build_report(args.incident_id)
    if report is None:
        raise SystemExit(f"no such incident {args.incident_id}")
    print(json.dumps(report, indent=2, default=str) if args.json else _md(report))
