"""MEASURE: the LLM's bounded contribution -- a diagnosis narrative. Its fault-class
hypothesis is ledgered and scored against the deterministic classification; it never
steers control flow. Any failure here degrades to an empty narrative, never a stall.
"""
from shared import classify, ddb, ledger, model_provider
from shared.log import log


def lambda_handler(event, context):
    iid = event["incident_id"]
    diff = event.get("diff", [])
    deterministic = event.get("fault_class", "unknown")

    try:
        diagnosis = model_provider.diagnose(diff, classify.FAULT_CLASSES)
    except Exception as e:  # noqa: BLE001
        log("diagnose_failed", incident_id=iid, error=str(e)[:300])
        diagnosis = {"fault_class": "unknown", "summary": "", "impact": ""}

    agreement = diagnosis["fault_class"] == deterministic
    ledger.append(iid, "MEASURE", "prompt", "llm",
                  {"llm_fault_class": diagnosis["fault_class"], "deterministic": deterministic,
                   "agreement": agreement, "summary": diagnosis["summary"],
                   "impact": diagnosis["impact"]})
    ddb.update_incident(iid, llm_fault_class=diagnosis["fault_class"],
                        llm_summary=diagnosis["summary"])
    log("diagnosed", incident_id=iid, llm=diagnosis["fault_class"],
        deterministic=deterministic, agreement=agreement)
    return diagnosis
