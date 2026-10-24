#!/usr/bin/env python3
"""In-process API test using FastAPI TestClient."""
import sys
sys.path.insert(0, ".")

from fastapi.testclient import TestClient
from tridetect.gateway.main import app
from tridetect.shared.db import init_db

init_db()

client = TestClient(app, raise_server_exceptions=True)

print("=== TEST 1: Health check ===")
r = client.get("/health")
assert r.status_code == 200, f"Expected 200, got {r.status_code}"
data = r.json()
print(f"  OK | status={data['status']} version={data['version']}")
print(f"  modules={data['modules']}")

print()
print("=== TEST 2: Web phishing (malicious URL) ===")
r = client.post("/v1/classify/web", json={"url": "http://g0pay-verify.tk/check", "check_ssl": False})
assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
data = r.json()
label = data["label"]
result = "PASS" if label in ("suspicious", "malicious") else "FAIL"
print(f"  {result} | label={label} confidence={data['confidence']:.1%} brand={data.get('brand_match')}")
for reason in data.get("reasons", [])[:3]:
    print(f"    - {reason}")

print()
print("=== TEST 3: Smishing (phishing SMS) ===")
r = client.post("/v1/classify/sms", json={
    "text": "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: bit.ly/xxx"
})
assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
data = r.json()
label = data["label"]
urg = data.get("urgency_score", 0)
result = "PASS" if label in ("suspicious", "malicious") else "FAIL"
print(f"  {result} | label={label} confidence={data['confidence']:.1%} urgency={urg}/100")
for reason in data.get("reasons", [])[:3]:
    print(f"    - {reason}")

print()
print("=== TEST 4: Voice (501 stub) ===")
r = client.post("/v1/classify/voice", json={"language": "id"})
result = "PASS" if r.status_code == 501 else "FAIL"
print(f"  {result} | HTTP {r.status_code}")
data = r.json()
if "detail" in data:
    print(f"  Phase 2 stub message: {data['detail'][:80]}...")

print()
print("=== TEST 5: Safe URL ===")
r = client.post("/v1/classify/web", json={"url": "https://www.tokopedia.com", "check_ssl": False})
assert r.status_code == 200
data = r.json()
label = data["label"]
result = "PASS" if label == "safe" else "WARN"
print(f"  {result} | label={label} confidence={data['confidence']:.1%}")

print()
print("All API tests complete!")
