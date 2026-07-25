# ADR 0006: A write-only CloudTrail trail is required for EventBridge detection

**Status**: accepted (2026-07-24)

## Context
The design assumed EventBridge receives `AWS API Call via CloudTrail` events without any
trail. Verified empirically during Phase 2: with no trail in the account, a matching
`RevokeSecurityGroupIngress` produced zero rule triggers in 30 minutes; after creating a
trail, the same event was detected in ~45 seconds.

## Decision
The platform stack includes a single-region, **write-only management events** trail to a
dedicated S3 bucket with a 1-day lifecycle. Write-only matters twice: the first copy of
management events is free, and it excludes the platform's own high-volume `Describe*`
calls (the PROVE snapshot alone makes five per incident).

## Consequences
- Detection latency is CloudTrail's delivery latency (~45s–5min observed) — measured and
  absorbed by eval timeouts, and honestly reported in MTTR numbers.
- Bucket contents never accrue (1-day expiry); teardown empties it before stack delete.
