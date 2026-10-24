#!/usr/bin/env python3
"""Live API endpoint test."""
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://localhost:8000"


def post(path, data):
    url = BASE + path
    req = urllib.request.Request(
        url,
        json.dumps(data).encode(),
        {"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code
    except Exception as e:
        return {"error": str(e)}, 0


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=5) as r:
            return json.loads(r.read()), r.status
    except Exception as e:
        return {"error": str(e)}, 0


print("=== TEST 1: Health check ===")
data, status = get("/health")
if "error" not in data:
    print(f"  OK | status={data.get('status')} version={data.get('version')}")
    print(f"  modules={data.get('modules')}")
else:
    print(f"  FAIL: {data}")

print()
print("=== TEST 2: Web phishing (malicious URL) ===")
data, status = post("/v1/classify/web", {"url": "http://g0pay-verify.tk/check", "check_ssl": False})
if "error" not in data:
    label = data.get("label")
    conf = data.get("confidence", 0)
    result = "PASS" if label in ("suspicious", "malicious") else "FAIL"
    print(f"  {result} | label={label} confidence={conf:.1%} brand={data.get('brand_match')}")
    for r in data.get("reasons", [])[:3]:
        print(f"    - {r}")
else:
    print(f"  FAIL HTTP {status}: {data}")

print()
print("=== TEST 3: Smishing (phishing SMS) ===")
data, status = post("/v1/classify/sms", {
    "text": "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: bit.ly/xxx",
})
if "error" not in data:
    label = data.get("label")
    urg = data.get("urgency_score", 0)
    result = "PASS" if label in ("suspicious", "malicious") else "FAIL"
    print(f"  {result} | label={label} urgency={urg}/100")
    for r in data.get("reasons", [])[:3]:
        print(f"    - {r}")
else:
    print(f"  FAIL HTTP {status}: {data}")

print()
print("=== TEST 4: Voice (501 stub) ===")
data, status = post("/v1/classify/voice", {"language": "id"})
result = "PASS" if status == 501 else "FAIL"
print(f"  {result} | HTTP {status}")
if "detail" in data:
    print(f"  Detail: {data['detail'][:80]}...")

print()
print("=== TEST 5: Safe URL (false negative check) ===")
data, status = post("/v1/classify/web", {"url": "https://www.tokopedia.com", "check_ssl": False})
if "error" not in data:
    label = data.get("label")
    result = "PASS" if label == "safe" else "WARN"
    print(f"  {result} | label={label} confidence={data.get('confidence', 0):.1%}")
else:
    print(f"  FAIL: {data}")
