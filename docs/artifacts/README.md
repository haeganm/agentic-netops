# Preserved runtime evidence

The platform is torn down to a $0 idle bill between demos, and DynamoDB point-in-time recovery
**dies with the table** — so these files are the only surviving record of what the system actually
did while it was live. Captured 2026-07-25, immediately before teardown.

A rebuild (`scripts/restore.ps1`) reconstructs the platform but starts with an empty ledger. None
of this is recoverable from the templates.

| File | What it is |
|---|---|
| `ledger-verification-cd5ead973ec1.txt` | Output of `scripts/verify_ledger.py` against the live table: the hash chain recomputed and confirmed **VALID**, 10 entries, head `ae492236b06f89ff…`. |
| `evidence-cd5ead973ec1.json` / `.md` | The full compliance evidence export for the same incident — six control assertions, each backed by ledger evidence (ADR 0015). |
| `dynamodb-final-export.json` | Raw `dynamodb scan` of the whole table: 739 items — 70 incidents, their complete ledger chains, 8 eval records, the baseline snapshot, the approver map, and the Reachability Analyzer counter at `used=25`. |

## Why incident `cd5ead973ec1` specifically

It is the worked example used in the project's public write-up: a `sg-ingress-removed` fault
detected, proved, repaired and verified **with no human involvement**, MTTR 132 s, LOW tier. Its
ledger is the one that reads as an evidence chain end to end — Reachability Analyzer attesting
`reachable: false` at entry 5 and `reachable: true` at entry 10, with the intent oracle's diff
going 1 → 0 in between.

Entry 10's `entry_hash` **is** the chain head, which is what the out-of-band SNS anchor published
(ADR 0014). So the claim "this record has not been altered" remains checkable from these files
alone, against a hash that was mailed out of band while the system was running.

## Note on redaction

These files intentionally keep their original AWS account ID, IAM ARNs, and resource IDs.
Every ledger entry's hash covers its full content, so redacting any field would make the
export fail its own `verify_ledger.py` check — the evidence would read as tampered, which is
the one thing a tamper-evidence artifact must not do. Account IDs are not credentials, the
resources no longer exist (the stack is torn down to $0), and no secret material was ever
written to the ledger.

## Note on lifetime cost

`dynamodb-final-export.json` records `LIMITS#RA used=25` — 25 Reachability Analyzer analyses,
about $2.50, at teardown. A rebuild reseeds that counter to `0/30`, so the in-code hard cap is
**per deployment, not per project lifetime**. `docs/costs.md` is the hand-maintained record of
true cumulative spend; treat that as authoritative, not the counter.
