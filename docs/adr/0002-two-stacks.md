# ADR 0002: Two stacks — the lab network is a separate deployable from the platform

**Status**: accepted (2026-07-24)

## Context
The platform's whole premise is "converge live network state to declared intent". The intent
source must be stable while the platform itself iterates daily.

## Decision
`netops-lab` (plain CloudFormation, lab/template.yaml) holds only the network under
management and is the drift target chaos breaks. `netops-platform` (SAM) holds everything
else and takes lab resource IDs as parameters. Remediation is targeted EC2 API reverts
derived from the baseline diff — never a stack update, which couldn't be scoped per-resource
and would race the approval gate.

## Consequences
- Platform redeploys (many per day during development) cannot disturb the drift target —
  and a mid-incident `sam deploy` is actually part of the demo (durable resume).
- Lab deploys are rare and wrapped in a maintenance-mode flag so the detector ignores
  CloudFormation's own changes.
