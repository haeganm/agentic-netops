"""Local parity ($0, no AWS): run the deterministic spine of the loop --
diff -> classify -> plan -> gate -- against an in-memory lab, optionally with
LLM diagnosis via local Ollama.

  python scripts/local_incident.py sg-ingress-removed [--ollama]
"""
import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from shared import classify, plan, policy

INVENTORY = {"vpc_id": "vpc-1", "sg_ids": ["sg-anchor", "sg-probe"], "rt_ids": ["rtb-pub"],
             "nacl_id": "acl-1", "subnet_ids": ["subnet-pub", "subnet-priv"],
             "eni_ids": ["eni-priv"], "igw_id": "igw-1"}

BASELINE = {
    "sgs": {"sg-anchor": {"ingress": [json.dumps({"cidr": "10.42.0.0/24", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)], "egress": []},
            "sg-probe": {"ingress": [], "egress": [json.dumps({"cidr": "0.0.0.0/0", "from": 443, "proto": "tcp", "to": 443}, sort_keys=True)]}},
    "route_tables": {"rtb-pub": {"routes": [json.dumps({"dest": "0.0.0.0/0", "state": "active", "target": "igw-1"}, sort_keys=True)], "subnets": ["subnet-pub"]}},
    "nacls": {"acl-1": {"entries": [], "subnets": ["subnet-priv"]}},
    "vpc": {"vpc-1": {"dns_support": True, "dns_hostnames": True}},
    "enis": {"eni-priv": {"sgs": ["sg-probe"]}},
}


def mutate(live: dict, fault: str) -> None:
    if fault == "sg-ingress-removed":
        live["sgs"]["sg-anchor"]["ingress"] = []
    elif fault == "sg-open-world":
        live["sgs"]["sg-anchor"]["ingress"].append(json.dumps({"cidr": "0.0.0.0/0", "from": 22, "proto": "tcp", "to": 22}, sort_keys=True))
    elif fault == "sg-egress-removed":
        live["sgs"]["sg-probe"]["egress"] = []
    elif fault == "route-deleted":
        live["route_tables"]["rtb-pub"]["routes"] = []
    elif fault == "route-blackholed":
        live["route_tables"]["rtb-pub"]["routes"] = [json.dumps({"dest": "0.0.0.0/0", "state": "blackhole", "target": "eni-dead"}, sort_keys=True)]
    elif fault == "nacl-deny-inserted":
        live["nacls"]["acl-1"]["entries"] = [json.dumps({"action": "deny", "cidr": "0.0.0.0/0", "egress": True, "from": None, "proto": "-1", "rule": 50, "to": None}, sort_keys=True)]
    elif fault == "rtb-assoc-swapped":
        live["route_tables"]["rtb-pub"]["subnets"] = ["subnet-pub", "subnet-priv"]
    elif fault == "sg-swapped-on-eni":
        live["enis"]["eni-priv"]["sgs"] = ["sg-anchor"]
    elif fault == "dns-disabled":
        live["vpc"]["vpc-1"]["dns_support"] = False
    else:
        raise SystemExit(f"unknown fault {fault}")


def main():
    from shared import baseline as base_mod
    ap = argparse.ArgumentParser()
    ap.add_argument("fault")
    ap.add_argument("--ollama", action="store_true")
    args = ap.parse_args()

    live = copy.deepcopy(BASELINE)
    mutate(live, args.fault)
    diff = base_mod.diff(BASELINE, live)
    fault_class = classify.classify(diff)
    ops = plan.build(diff, BASELINE)
    gate = policy.evaluate(ops, diff, BASELINE, INVENTORY)

    print(f"PROVE            diff entries: {len(diff)}")
    print(f"PROVE            deterministic class: {fault_class}  (label: {args.fault})")
    if args.ollama:
        from shared import model_provider
        d = model_provider.diagnose(diff, classify.FAULT_CLASSES)
        print(f"MEASURE (llm)    class: {d['fault_class']}  agree: {d['fault_class'] == fault_class}")
        print(f"MEASURE (llm)    {d['summary']}")
    print(f"GENERATE-REPAIR  ops: {json.dumps(ops, indent=1)}")
    print(f"GATE             {gate['verdict']} (policy {gate['policy_version']}) {gate['violations']}")
    assert fault_class == args.fault and gate["verdict"] == "PASS"
    print("local loop spine OK")


if __name__ == "__main__":
    main()
