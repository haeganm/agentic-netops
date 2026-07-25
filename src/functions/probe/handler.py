"""Data-plane oracle. Runs INSIDE the lab private subnet with no NAT, so it makes zero
AWS SDK calls -- Step Functions invokes it over the control plane and reads the verdict
from the response. DNS check proves the VPC resolver/attributes; the raw TCP connect to
S3 (via the free gateway endpoint) traverses ProbeSg egress, the private NACL both
directions, and the private route table's prefix-list route.
"""
import os
import socket
import time


def lambda_handler(event, context):
    host = os.environ.get("PROBE_HOST", "s3.us-east-1.amazonaws.com")
    verdict = {"dns": "fail", "tcp": "fail", "latency_ms": None, "host": host}

    t0 = time.time()
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        verdict["dns"] = "pass"
        verdict["ip"] = ip
    except OSError as e:
        verdict["error"] = f"dns: {e}"
        return verdict

    try:
        with socket.create_connection((ip, 443), timeout=5):
            verdict["tcp"] = "pass"
        verdict["latency_ms"] = round((time.time() - t0) * 1000)
    except OSError as e:
        verdict["error"] = f"tcp: {e}"
    return verdict
