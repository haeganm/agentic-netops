# ADR 0007: The one managed-policy exception — Reachability Analyzer's permission set

**Status**: accepted (2026-07-24)

## Context
Project rule (inherited from v1): inline least-privilege statements only, no managed
policies. Reachability Analyzer broke this twice in live testing: `StartNetworkInsightsAnalysis`
failed on `tiros:CreateQuery`; after granting `tiros:*` + `ec2:Describe*` inline, analyses
still failed mid-run with "insufficient permissions" — the engine walks the network graph
with the *caller's* credentials and requires describe access across services we don't use
(ELB, Direct Connect, Network Firewall, …).

## Decision
Attach AWS-managed `AmazonVPCReachabilityAnalyzerFullAccessPolicy` to the oracles function
only. AWS owns that action list and evolves it with the service; recreating it inline is
guaranteed drift. Every other function in the project keeps inline least-privilege.

## Consequences
- The oracles function has read permissions broader than the lab strictly needs — bounded
  to read + analysis-creation actions, on the one function whose job is analysis.
- Two other live-verified IAM facts recorded here: CFN drift detection needs
  `cloudformation:DetectStackResourceDrift` in addition to `DetectStackDrift`; Bedrock
  cross-region inference profiles need the foundation-model ARN with a wildcard region.
