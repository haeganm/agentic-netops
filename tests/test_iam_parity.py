"""The mutating-EC2-action set is duplicated across four places (gate allowlist, STS scoper,
and the boundary + role IAM in template.yaml). They agree today; nothing else enforces it.
These tests fail loudly if a future edit desyncs them (which would cause either a runtime
AccessDenied or a gate that blocks a legitimate fix).

The template is PARSED, not grepped: an earlier regex version matched `ec2:` mentions inside
comments and mistook IAM condition keys (dynamodb:LeadingKeys, states:StateMachineArn) for
action verbs.
"""
import json
import os

import yaml

from shared import policy, sts_scope

ROOT = os.path.join(os.path.dirname(__file__), "..")
TEMPLATE = os.path.join(ROOT, "template.yaml")
ASL = os.path.join(ROOT, "statemachine", "incident.asl.json")


class _CfnLoader(yaml.SafeLoader):
    """Tolerates CloudFormation short-form intrinsics (!Ref, !Sub, !GetAtt, ...)."""


def _intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return f"!{tag_suffix} {node.value}"
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", _intrinsic)


def _template() -> dict:
    with open(TEMPLATE) as f:
        return yaml.load(f, Loader=_CfnLoader)


def _actions_in(doc) -> set:
    """Every Action string anywhere inside an IAM policy document (recursive)."""
    found = set()
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "Action":
                found.update([v] if isinstance(v, str) else [a for a in v if isinstance(a, str)])
            else:
                found |= _actions_in(v)
    elif isinstance(doc, list):
        for item in doc:
            found |= _actions_in(item)
    return found


def _all_iam_actions() -> set:
    return _actions_in(_template()["Resources"])


def test_gate_and_scoper_action_sets_match():
    assert set(sts_scope.ACTION_MAP) == policy.ALLOWED_ACTIONS


def test_iam_matches_scoper():
    """Every mutating ec2 action the scoper can emit must be grantable, and vice versa."""
    scoper = {v[0] for v in sts_scope.ACTION_MAP.values()}
    template_mutating = {a for a in _all_iam_actions()
                         if a.startswith("ec2:") and not a.startswith("ec2:Describe")}
    assert scoper == template_mutating, (
        f"IAM/scoper drift: only in scoper={scoper - template_mutating}, "
        f"only in template={template_mutating - scoper}")


def test_state_machine_has_no_ec2_mutations():
    """ALL network mutation goes through the executor's scoped RemediationRole -- never a
    native ASL integration. The tier paths must not change that."""
    with open(ASL) as f:
        asl = json.load(f)
    for name, state in asl["States"].items():
        assert "ec2" not in str(state.get("Resource", "")), f"{name} mutates EC2 directly"


def test_api_function_iam_is_read_plus_callbacks_only():
    """The console API may read, write INCIDENT#* items, and complete callback tokens --
    nothing else. cancel/verify/evidence added no new verb."""
    api = _template()["Resources"]["ApiFunction"]["Properties"]["Policies"]
    assert _actions_in(api) <= {
        "states:SendTaskSuccess", "states:SendTaskFailure",
        "dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem",
    }


def test_fault_classes_and_oracle_policy_agree():
    """A fault class with no oracle policy silently falls back to the config-drift default."""
    from shared import classify
    assert set(classify.FAULT_CLASSES) == set(classify.ORACLE_POLICY)
