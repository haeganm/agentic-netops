# Compliance evidence - incident cd5ead973ec1
- status: **RESOLVED** | fault: sg-ingress-removed | MTTR: 132s
- ledger entries: 10

## Control assertions
**Change authorized** - tier `LOW`; authorized by policy (auto-execute, veto window); approvals: none
**Least privilege** - scoped STS session policy recomputed: True; applied ops: [{'action': 'authorize_security_group_ingress', 'result': 'ok'}]
**Verified** - intent [{'stage': 'PROVE', 'diff_count': 1}, {'stage': 'VERIFY', 'diff_count': 0}]; impact reachability {'MEASURE': False, 'VERIFY': True}; data-plane []; scope: full
**Within policy** - gate PASS (policy 2.0.0), violations: []
**Human oversight** - drift caused by `arn:aws:iam::559007813069:user/haegan-admin`; approvers: none (auto-executed under a veto window); SoD evaluated: False; two-party: False
**Tamper-evident** - ledger chain **VALID** (len 10, head `ae492236b06f89ff...`)
