# ADR 0008: Reachability Analyzer's authority ends at IGW egress in a no-public-IP lab

**Status**: accepted (2026-07-24)

## Context
Route-class faults (route-deleted, route-blackholed) originally used an RA path
AnchorEniPublic → IGW as their impact/verify oracle. Live eval runs failed VERIFY even
after a provably correct repair (intent re-diff empty). Two controlled spikes explained it:
without a destination IP the path reports `NO_ROUTE_TO_DESTINATION`; with one, RA reports
`IGW_PUBLIC_IP_ASSOCIATION_FOR_EGRESS` — RA correctly models that internet egress requires
a public IP on the source, and this lab deliberately has none (an EIP is ~$3.60/month of
idle spend, violating the $0-idle constraint).

## Decision
Route classes verify by the intent oracle (baseline re-diff must be empty) plus CFN drift
corroboration; RA is not consulted for them. The oracle-selection table in
`src/shared/classify.py` is the single source of truth for which oracle can adjudicate
which fault class, and this boundary is documented rather than papered over.

## Consequences
- Every verification claim stays true: RA "reachable" flips are only claimed for paths RA
  can actually model (intra-VPC ENI-to-ENI).
- Documented upgrade path: attach an EIP to the public anchor ENI and route classes regain
  an RA verdict, at ~$3.60/month.
- This is the project thesis in miniature: know precisely where each oracle's authority
  ends, and label verification accordingly.
