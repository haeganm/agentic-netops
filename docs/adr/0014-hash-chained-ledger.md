# ADR 0014: Tamper-evident hash-chained decision ledger

**Status**: accepted (2026-07-24)

## Context
The platform now auto-executes some remediations without a human (autonomy tiers, ADR 0011).
That raises the bar on the audit trail: an auditor — or an incident responder after a
compromise — must be able to prove that no ledger entry was altered, inserted, or deleted
after the fact. A plain append-only list doesn't provide that; an in-account role with table
write access could rewrite history.

## Decision
Every ledger entry is a link in a per-incident hash chain. Each entry carries `seq`
(contiguous from 1), `prev_hash` (the chain head before it), and
`entry_hash = sha256(prev_head + canonical(entry))`. A per-incident `LEDGER_HEAD` item holds
the latest `{seq, head_hash}`; genesis is 64 zero hex.

`append` advances the head under an **optimistic lock** on its `seq` (a conditional
`UpdateItem`), which is the serialization point: two concurrent appends to the same incident
cannot both claim the same seq — the loser's condition fails and it retries against the new
head. The entry is written after the head advances. (TransactWriteItems would give
single-call atomicity, but moto can't emulate it in this version; the head-lock + entry-put
gives the same integrity guarantee — a crash between the two writes leaves a detectable
head/entry mismatch, never a silent gap.)

`verify_ledger(incident_id)` replays genesis → head and returns
`{valid, length, head, first_break_seq}`. Any alteration changes an entry_hash; any deletion
breaks seq contiguity; any insertion fails the prev_hash link — each surfaces as
`valid=False` at the exact `first_break_seq`.

On **every** terminal outcome — resolved, verification-limited, false-positive, cancelled,
expired, rejected, and failed — an `AnchorLedger` state invokes
`functions/governance:anchor_ledger`, which records `chain_head`/`chain_len` on the incident and
publishes the head **out of band** to the alert topic. Out-of-band is the whole point: a role
with table write access could rewrite the entries *and* the `LEDGER_HEAD` item consistently, so
the emailed copy of the head is what makes after-the-fact tampering detectable. Anchoring
failures are caught and never fail an otherwise-resolved incident (the chain is already durable
in the table); PITR + deletion protection back it further.

Failed and cancelled incidents are anchored too, deliberately: a failed remediation attempt is
exactly the history worth erasing. `tests/test_statemachine.py::test_every_terminal_outcome_anchors_the_ledger`
enforces that no terminal path can skip it.

## Consequences
- Any post-hoc tampering with an incident's history is cryptographically detectable, and the
  compliance evidence export (ADR 0015) includes the verification result.
- A crash between head-advance and entry-write is detected as invalid — a false *positive*
  for tampering, resolved by inspection. Documented as detected-benign in docs/SECURITY.md.
- Fully independent notarization (QLDB / S3 Object Lock / an external timestamping service)
  is the documented next step when this leaves the lab.
- `# ponytail: single-item optimistic lock; fine at lab volume; per-account write sharding
  only if append throughput ever becomes the bottleneck.`
