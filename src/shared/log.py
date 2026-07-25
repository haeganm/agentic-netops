"""Structured JSON logging. Log IDs, timings, counts - never prompt/config payloads."""
import json
import sys
import time


def log(event: str, **fields) -> None:
    print(json.dumps({"event": event, "ts": round(time.time(), 3), **fields}), file=sys.stdout)
