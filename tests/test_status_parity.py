"""The incident-status vocabulary has one home (shared/status.py) and three read-side copies
with no type checker across the boundary: demo.ps1's terminal poll list, evaluate.py's
TERMINAL set, and the console's styled status classes. status.py's own docstring records that
exactly this drift already happened once (terminal lists missing CANCELLED, a styled status
nothing set) -- these are the parity guards conventions.md promises. Set EQUALITY, not subset:
a stale member is as wrong as a missing one.
"""
import os
import re

from shared import status

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def test_demo_ps1_terminal_list_matches():
    m = re.search(r"\$terminal = @\(([^)]*)\)", _read("scripts", "demo.ps1"), re.S)
    assert m, "demo.ps1 no longer declares $terminal -- update this extractor"
    assert set(re.findall(r'"([A-Z_]+)"', m.group(1))) == status.TERMINAL


def test_evaluate_py_terminal_set_matches():
    m = re.search(r"TERMINAL = \{([^}]*)\}", _read("scripts", "evaluate.py"), re.S)
    assert m, "evaluate.py no longer declares TERMINAL -- update this extractor"
    assert set(re.findall(r'"([A-Z_]+)"', m.group(1))) == status.TERMINAL


def test_console_styles_exactly_the_declared_statuses():
    styled = set(re.findall(r"\.s-([A-Z_]+)", _read("ui", "index.html")))
    assert styled == status.ALL, f"console/status drift: {styled ^ status.ALL}"


def test_console_refresh_list_matches_in_flight():
    # the detail view keeps auto-refreshing exactly while the incident is in flight
    m = re.search(r"\[([^\]]+)\]\.includes\(meta\.status\)", _read("ui", "index.html"), re.S)
    assert m, "console no longer gates its refresh on a status list -- update this extractor"
    assert set(re.findall(r'"([A-Z_]+)"', m.group(1))) == status.IN_FLIGHT
