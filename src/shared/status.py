"""The incident status vocabulary -- single source of truth.

The state machine is the only WRITER of these values (native dynamodb:updateItem states), while
Python, PowerShell and the browser all READ them. There is no type checker across that boundary,
so the set was previously re-typed in seven places and had already drifted: two terminal-status
lists were missing CANCELLED (making a correct outcome poll until timeout) and the console styled
a MEASURING status nothing ever set.

tests/test_statemachine.py asserts every status literal in the ASL is a member of ALL.
"""

# --- in flight -------------------------------------------------------------------------------
DETECTED = "DETECTED"                                   # created by the detector, loop not started
PROVING = "PROVING"                                     # intent oracle running
AWAITING_APPROVAL = "AWAITING_APPROVAL"                 # MEDIUM/HIGH: first human decision
AWAITING_SECOND_APPROVAL = "AWAITING_SECOND_APPROVAL"   # HIGH: distinct second approver (ADR 0013)
AUTO_EXEC_PENDING = "AUTO_EXEC_PENDING"                 # LOW: veto window open (ADR 0012)
EXECUTING = "EXECUTING"                                 # applying the approved plan

# --- terminal --------------------------------------------------------------------------------
RESOLVED = "RESOLVED"                                   # converged and fully verified
VERIFICATION_LIMITED = "VERIFICATION_LIMITED"           # converged, an impact check was skipped (ADR 0005)
FALSE_POSITIVE = "FALSE_POSITIVE"                       # no drift found; nothing to do
CANCELLED = "CANCELLED"                                 # a human vetoed the auto-execute
REJECTED = "REJECTED"                                   # a human declined the plan
EXPIRED = "EXPIRED"                                     # no decision inside the approval window
GATE_BLOCKED = "GATE_BLOCKED"                           # the policy gate refused the plan
FAILED = "FAILED"                                       # the loop could not complete

IN_FLIGHT = frozenset({DETECTED, PROVING, AWAITING_APPROVAL, AWAITING_SECOND_APPROVAL,
                       AUTO_EXEC_PENDING, EXECUTING})

# a repair happened and converged (verification depth differs)
REMEDIATED = frozenset({RESOLVED, VERIFICATION_LIMITED})

TERMINAL = frozenset({RESOLVED, VERIFICATION_LIMITED, FALSE_POSITIVE, CANCELLED, REJECTED,
                      EXPIRED, GATE_BLOCKED, FAILED})

# statuses at which a human decision is pending on a stored task token
AWAITING_DECISION = frozenset({AWAITING_APPROVAL, AWAITING_SECOND_APPROVAL, AUTO_EXEC_PENDING})

ALL = IN_FLIGHT | TERMINAL
