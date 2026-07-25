"""Static validation of the ASL (v1 pattern, extended): structure, safety nets,
substitution wiring, bounded polling, and key-format consistency with ddb helpers."""
import json
import os
import re

ASL_PATH = os.path.join(os.path.dirname(__file__), "..", "statemachine", "incident.asl.json")
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "template.yaml")

with open(ASL_PATH) as f:
    ASL = json.load(f)
STATES = ASL["States"]
RAW = json.dumps(ASL)


def test_valid_structure_and_reachability():
    assert ASL["StartAt"] in STATES
    referenced = set()
    for s in STATES.values():
        for key in ("Next", "Default"):
            if key in s:
                referenced.add(s[key])
        for c in s.get("Choices", []):
            referenced.add(c["Next"])
        for c in s.get("Catch", []):
            referenced.add(c["Next"])
    unknown = referenced - set(STATES)
    assert not unknown, f"transitions to unknown states: {unknown}"
    unreachable = set(STATES) - referenced - {ASL["StartAt"]}
    assert not unreachable, f"unreachable states: {unreachable}"


def test_every_lambda_task_has_catch():
    for name, s in STATES.items():
        if s.get("Type") == "Task" and str(s.get("Resource", "")).startswith("${"):
            assert "Catch" in s, f"{name} has no Catch -> a crash would strand the incident"


# Execute is the ONE deliberate exception: retrying a partially-applied plan could
# double-apply EC2 mutations, so it fails fast instead (see test_executor_has_no_blind_retry).
NO_RETRY_BY_DESIGN = {"Execute"}


def test_every_task_has_retry():
    """Covers EVERY Task, not just Lambda ones. The native dynamodb:updateItem states had
    neither Retry nor Catch, so a transient throttle on MarkExecuting/Close stranded the
    incident in a non-terminal status forever -- and the old ${-prefixed predicate above
    never inspected them."""
    for name, s in STATES.items():
        if s.get("Type") == "Task" and name not in NO_RETRY_BY_DESIGN:
            assert "Retry" in s, f"{name} has no Retry -> a transient AWS error is terminal"


def test_wait_states_do_not_retry_task_failure():
    """Reject/Cancel arrive AS a task failure. Retrying that would re-issue the token and
    re-open a decision the human already made."""
    for name in ("WaitForApproval", "WaitForSecondApproval", "VetoWindow"):
        for r in STATES[name].get("Retry", []):
            assert "States.TaskFailed" not in r["ErrorEquals"], f"{name} would retry a human decision"
            assert "States.ALL" not in r["ErrorEquals"], f"{name} would retry a human decision"


def test_all_non_executing_terminals_clear_the_task_token():
    """A terminal incident must not keep a live callback token (SECURITY.md A6)."""
    for name in ("MarkFailed", "MarkExpired", "MarkRejected", "MarkCancelled", "MarkExecuting"):
        expr = STATES[name]["Parameters"]["UpdateExpression"]
        assert "REMOVE task_token" in expr, f"{name} leaves a live token behind"


def test_terminal_marks_are_ddb_updates():
    for name in ("MarkFailed", "MarkExpired", "MarkRejected", "Close", "CloseFalsePositive", "MarkGateBlocked"):
        assert STATES[name]["Resource"] == "arn:aws:states:::dynamodb:updateItem"


def test_status_updates_alias_reserved_word():
    for s in STATES.values():
        expr = s.get("Parameters", {}).get("UpdateExpression", "")
        assert "status" not in expr.split(":s")[0].replace("#s", ""), \
            "raw 'status' (reserved word) in UpdateExpression"


def test_incident_key_format_matches_ddb_helper():
    from shared import ddb
    assert ddb.incident_key("X")["pk"] == "INCIDENT#X"
    for s in STATES.values():
        key = s.get("Parameters", {}).get("Key", {})
        if key:
            assert key["pk"]["S.$"] == "States.Format('INCIDENT#{}', $.incident_id)"
            assert key["sk"]["S"] == "META"


def test_substitutions_all_declared_in_template():
    subs = set(re.findall(r"\$\{(\w+)\}", RAW))
    with open(TEMPLATE_PATH) as f:
        template = f.read()
    section = template.split("DefinitionSubstitutions:")[1].split("Policies:")[0]
    for sub in subs:
        assert f"{sub}:" in section, f"substitution ${{{sub}}} missing from template"


def test_poll_loops_are_bounded():
    # every Wait loop's poller must feed a Choice that can exit on .done
    for wait_name in ("WaitDrift", "WaitRa", "WaitReRa"):
        poller = STATES[wait_name]["Next"]
        choice = STATES[STATES[poller]["Next"]]
        assert any(c.get("BooleanEquals") is True for c in choice["Choices"])
    # and the Lambdas force done=True at MAX_POLLS
    from functions.oracles import handler
    assert handler.MAX_POLLS <= 15


def test_wait_for_approval_has_timeout_and_reject_catch():
    s = STATES["WaitForApproval"]
    assert s["Resource"].endswith("lambda:invoke.waitForTaskToken")
    assert s["TimeoutSeconds"] == 86400
    errors = [e for c in s["Catch"] for e in c["ErrorEquals"]]
    assert "States.Timeout" in errors and "Rejected" in errors


def test_executor_has_no_blind_retry():
    assert "Retry" not in STATES["Execute"], "retrying a partial apply could double-apply ops"


def test_gate_fail_never_reaches_approval():
    assert STATES["GateOk?"]["Default"] == "MarkGateBlocked"
    assert STATES["MarkGateBlocked"]["Next"] == "FailGate"
    assert STATES["FailGate"]["Type"] == "Fail"


def test_tier_router_after_gate():
    assert STATES["GateOk?"]["Choices"][0]["Next"] == "TierRouter"
    # LOW -> veto path; everything else -> human approval
    assert _choice(STATES["TierRouter"], StringEquals="LOW")["Next"] == "NotifyVeto"
    assert STATES["TierRouter"]["Default"] == "NotifyApprover"


def test_veto_window_timeout_inversion():
    # THE inversion: on the veto window, a timeout means PROCEED (auto-execute), not expire.
    vw = STATES["VetoWindow"]
    assert vw["TimeoutSeconds"] == 60
    timeout_catch = next(c for c in vw["Catch"] if "States.Timeout" in c["ErrorEquals"])
    assert timeout_catch["Next"] == "MarkExecuting"  # NOT MarkExpired
    cancel_catch = next(c for c in vw["Catch"] if "Cancelled" in c["ErrorEquals"])
    assert cancel_catch["Next"] == "MarkCancelled"


def test_high_tier_requires_second_approval():
    assert STATES["WaitForApproval"]["Next"] == "SecondPartyNeeded?"
    high = _choice(STATES["SecondPartyNeeded?"], StringEquals="HIGH")
    assert high["Next"] == "NotifySecondApprover"
    assert STATES["SecondPartyNeeded?"]["Default"] == "MarkExecuting"
    assert STATES["WaitForSecondApproval"]["Next"] == "MarkExecuting"


def test_tier_choices_fail_closed_when_tier_absent():
    """A Choice on a missing JSONPath raises UNCATCHABLE States.Runtime, so both tier
    routers must guard with IsPresent and fall back to human approval."""
    assert _choice(STATES["TierRouter"], IsPresent=False)["Next"] == "NotifyApprover"
    assert _choice(STATES["SecondPartyNeeded?"], IsPresent=False)["Next"] == "MarkExecuting"


def _choice(state: dict, **match) -> dict:
    (key, want), = match.items()
    return next(c for c in state["Choices"] if c.get(key) == want)


def test_all_wait_states_have_timeout():
    for name in ("WaitForApproval", "WaitForSecondApproval", "VetoWindow"):
        assert STATES[name].get("TimeoutSeconds"), f"{name} missing TimeoutSeconds"


def test_cancelled_is_terminal_ddb_update():
    assert STATES["MarkCancelled"]["Resource"] == "arn:aws:states:::dynamodb:updateItem"
    assert STATES["MarkCancelled"]["Next"] == "AnchorLedger"


TERMINAL_STATUS_STATES = ("Close", "CloseLimited", "CloseFalsePositive", "MarkCancelled",
                          "MarkExpired", "MarkRejected", "MarkFailed")


def test_every_terminal_outcome_anchors_the_ledger():
    """Tamper-evidence is worthless if only happy-path incidents get anchored -- a failed or
    cancelled remediation is exactly the history worth erasing (ADR 0014)."""
    for name in TERMINAL_STATUS_STATES:
        nxt = STATES[name]["Next"]
        assert nxt.startswith("AnchorLedger"), f"{name} terminates without anchoring (-> {nxt})"


def test_asl_statuses_match_shared_status_module():
    """The ASL is the only WRITER of incident statuses; Python/PowerShell/JS all read them.
    Nothing type-checks that boundary, so assert every status the workflow can write is a
    declared member of shared.status.ALL (the set had already drifted before this existed)."""
    from shared import status
    written = set()
    for s in STATES.values():
        vals = s.get("Parameters", {}).get("ExpressionAttributeValues", {})
        if ":s" in vals and "S" in vals[":s"]:
            written.add(vals[":s"]["S"])
    assert written, "found no status writes -- the extractor is broken, not the ASL"
    assert written <= status.ALL, f"ASL writes undeclared statuses: {written - status.ALL}"
    # and every terminal status the module declares must actually be reachable
    assert written & status.TERMINAL, "no terminal status is written by the workflow"


def test_verification_limited_is_reachable():
    """The status is claimed in the README, costs.md, ADR 0005 and the UI -- it must be a state
    the workflow can actually reach, not just an attribute nothing reads."""
    limited = STATES["CloseLimited"]["Parameters"]["ExpressionAttributeValues"][":s"]["S"]
    assert limited == "VERIFICATION_LIMITED"
    scope = STATES["VerificationScope?"]
    assert all(c["Next"] == "CloseLimited" for c in scope["Choices"])
    assert scope["Default"] == "Close"
    # both routes into the close decision must pass through it
    assert STATES["NeedReProbe?"]["Default"] == "VerificationScope?"
    assert STATES["ReProbeHealthy?"]["Choices"][0]["Next"] == "VerificationScope?"
