"""Local parity: the deterministic spine (mutate -> diff -> classify -> plan -> gate) must
handle every seeded fault class with zero AWS. The README stakes a headline on this, and it
regressed once without any test noticing: a one-route-table fixture made rtb-assoc-swapped
unplannable (fixed in a668b7d). Parametrizing over chaos.FAULTS also means a new fault class
added to the seeder without a local mutation fails here, not at demo time.

scripts/ is not a package, so the two modules are loaded by file path.
"""
import copy
import importlib.util
import os

import pytest

from shared import baseline, classify, plan, policy

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "scripts")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPTS, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


local_incident = _load("local_incident")
chaos = _load("chaos")


@pytest.mark.parametrize("fault", chaos.FAULTS)
def test_spine_heals_every_seeded_class(fault):
    live = copy.deepcopy(local_incident.BASELINE)
    local_incident.mutate(live, fault)
    diff = baseline.diff(local_incident.BASELINE, live)
    assert diff, "mutation produced no drift"
    assert classify.classify(diff) == fault
    ops = plan.build(diff, local_incident.BASELINE)
    gate = policy.evaluate(ops, diff, local_incident.BASELINE, local_incident.INVENTORY)
    assert gate["verdict"] == "PASS", gate["violations"]
