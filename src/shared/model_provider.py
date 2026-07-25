"""LLM backend abstraction: Ollama (local, $0) or Bedrock (cloud, Nova Micro).

Selected via MODEL_PROVIDER env var. The LLM is a bounded component of the loop:
it drafts the diagnosis narrative and repair explanation. Its fault-class
hypothesis is SCORED against the deterministic classification, never trusted --
control flow is driven by shared/classify.py, not by anything returned here.
"""
import json
import os
import re
import urllib.request

from shared.log import log

MAX_DIFF_CHARS = 6000

# The prompt receives ONLY a structural diff summary (change type / resource type / field),
# built by us from the deterministic differ -- never raw CloudTrail text, tags, or rule
# descriptions. There is no attacker-writable free text in this prompt, so injected
# "instructions" have nothing to ride in on. The LLM's classification is scored against the
# deterministic classifier regardless, so this narrative can never steer the loop.
DIAGNOSE_PROMPT = """You are a network operations analyst. Below is a STRUCTURAL summary of a \
verified configuration diff between a VPC's declared baseline and its live state, produced by a \
deterministic differ. Classify the fault and describe its likely impact. Respond with ONLY a \
JSON object, no other text:
{{"fault_class": "<one of: {classes}>", "summary": "<2-3 sentence diagnosis>", "impact": "<1-2 sentences: what traffic/service is affected>"}}

Configuration drift (structural):
{diff}"""

EXPLAIN_REPAIR_PROMPT = """You are a network operations analyst. A deterministic planner produced \
the remediation plan below, which converges live VPC state back to its declared baseline. \
Write a plain-English rationale a human approver can read in 15 seconds. Respond with ONLY a \
JSON object: {{"rationale": "<2-4 sentences: what will change and why it is safe>"}}

Fault diagnosis: {diagnosis}

Remediation plan:
{plan}"""


def diagnose(diff: list, fault_classes: list[str]) -> dict:
    # structural-only: strip expected/actual values, keep just what's needed to name a class
    structural = [{"change": e.get("kind"), "resource_type": e.get("section"), "field": e.get("field")}
                  for e in (diff or [])]
    prompt = DIAGNOSE_PROMPT.format(
        classes=", ".join(fault_classes),
        diff=json.dumps(structural, default=str)[:MAX_DIFF_CHARS],
    )
    obj = _parse(_call(prompt))
    return {
        "fault_class": str(obj.get("fault_class", "unknown"))[:50],
        "summary": str(obj.get("summary", ""))[:2000],
        "impact": str(obj.get("impact", ""))[:1000],
    }


def explain_repair(diagnosis: str, plan: list[dict]) -> str:
    prompt = EXPLAIN_REPAIR_PROMPT.format(
        diagnosis=diagnosis[:1000], plan=json.dumps(plan, default=str)[:MAX_DIFF_CHARS]
    )
    return str(_parse(_call(prompt)).get("rationale", ""))[:2000]


def _call(prompt: str) -> str:
    provider = os.environ.get("MODEL_PROVIDER", "ollama")
    return _bedrock(prompt) if provider == "bedrock" else _ollama(prompt)


def _ollama(prompt: str) -> str:
    url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    model = os.environ.get("MODEL_ID", "llama3.2:1b")
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode()
    req = urllib.request.Request(f"{url}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = json.loads(resp.read())
    log("ollama_call", model=model, eval_count=data.get("eval_count"), prompt_eval_count=data.get("prompt_eval_count"))
    return data["response"]


def _bedrock(prompt: str) -> str:
    import boto3  # deferred: not needed for local ollama path

    model = os.environ.get("MODEL_ID", "us.amazon.nova-micro-v1:0")
    client = boto3.client("bedrock-runtime")
    resp = client.converse(
        modelId=model,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 800, "temperature": 0.1},
    )
    usage = resp.get("usage", {})
    log("bedrock_call", model=model, input_tokens=usage.get("inputTokens"), output_tokens=usage.get("outputTokens"))
    return resp["output"]["message"]["content"][0]["text"]


def _parse(raw: str) -> dict:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        try:
            obj = json.loads(m.group()) if m else {}
        except json.JSONDecodeError:
            obj = {}
    return obj if isinstance(obj, dict) else {}
