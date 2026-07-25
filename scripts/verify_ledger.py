"""Cryptographically verify an incident's decision ledger. Read-only.

  python scripts/verify_ledger.py <incident_id>
Exit 0 = chain intact; exit 1 = tampering detected (with the first broken seq).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import ledger

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_ledger.py <incident_id>")
    r = ledger.verify_ledger(sys.argv[1])
    if r["valid"]:
        print(f"VALID — {r['length']} entries, head {r['head'][:16]}...")
        sys.exit(0)
    print(f"BROKEN — chain fails at seq {r['first_break_seq']} (length {r['length']})")
    sys.exit(1)
