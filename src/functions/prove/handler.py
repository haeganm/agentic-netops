"""PROVE (mode=prove): snapshot live config, diff against declared baseline,
deterministically classify. VERIFY (mode=verify): re-diff must be empty.
The intent oracle in both cases is shared/baseline.py -- no LLM involvement.
"""
import json

from shared import baseline, classify, ddb, ledger
from shared.log import log

# how many diff entries to keep in the ledger sample (see the append call below)
LEDGER_DIFF_SAMPLE = 12


def lambda_handler(event, context):
    mode = event.get("mode", "prove")
    iid = event["incident_id"]
    stage = "PROVE" if mode == "prove" else "VERIFY"

    cfg = ddb.get_config("BASELINE")
    base = json.loads(cfg["snapshot"])
    inventory = json.loads(cfg["inventory"])
    live = baseline.snapshot(inventory)
    diff = baseline.diff(base, live)

    # Ledger a BOUNDED sample of the diff: the full diff on a wide drift exceeds the ledger's
    # payload clamp and would be sliced mid-JSON (unparseable). The authoritative full diff
    # travels in the workflow state; the ledger keeps the count plus a readable sample.
    ledger.append(iid, stage, "oracle_verdict", "oracle:intent",
                  {"diff_count": len(diff), "diff_sample": diff[:LEDGER_DIFF_SAMPLE],
                   "sampled": len(diff) > LEDGER_DIFF_SAMPLE})
    log("prove", incident_id=iid, mode=mode, diff_count=len(diff))

    if mode == "verify":
        return {"diff_count": len(diff)}

    fault_class = classify.classify(diff) if diff else None
    oracles = classify.oracles_for(fault_class) if diff else {}
    if diff:
        ddb.update_incident(iid, fault_class=fault_class)
    return {"diff_count": len(diff), "diff": diff, "fault_class": fault_class,
            "oracles": {"ra_path": oracles.get("ra_path"), "probe": bool(oracles.get("probe"))},
            "inventory": inventory}
