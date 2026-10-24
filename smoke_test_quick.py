#!/usr/bin/env python3
"""Quick web-only smoke test (no model download)."""
import sys
sys.path.insert(0, ".")

print("=== WEB PHISHING TEST ===")
from tridetect.modules.web_phishing.classifier import WebPhishingClassifier
clf = WebPhishingClassifier()

tests = [
    ("http://g0pay-verify.tk/check",     False, "malicious"),
    ("http://192.168.1.1/login",         False, "malicious"),   # IP addr = malicious
    ("http://mandiri-secure.xyz/login",  False, "malicious"),   # brand + bad TLD
    ("https://www.tokopedia.com",        False, "safe"),
    ("https://shopee.co.id",            False, "safe"),
    ("http://jne-tracking.ml/id",       False, "malicious"),
    ("http://bca-login.ga/auth",        False, "malicious"),
]

all_ok = True
for url, check_ssl, expected in tests:
    r = clf.classify(url, check_ssl=check_ssl)
    status = "OK" if r["label"] == expected else f"FAIL (expected {expected})"
    print(f"  [{r['label']:10s}] {r['confidence']:.1%}  {status} | {url}")
    if r["label"] != expected:
        all_ok = False

print()
print("=== SMISHING RULE-BASED TEST ===")
from tridetect.modules.smishing.preprocessor import preprocess
from tridetect.modules.smishing.urgency_scorer import compute_urgency
from tridetect.modules.smishing.number_reputation import check_number

tests_sms = [
    "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: bit.ly/gopayverify",
    "Selamat! Hadiah Rp 50.000.000 menunggu Anda. Klaim: jne-tracking.ml/id",
    "Kode OTP BCA Anda adalah 843921. Jangan bagikan kode ini.",
    "Halo, meeting besok jam 09.00 WIB di ruang rapat.",
]

for sms in tests_sms:
    p = preprocess(sms)
    urg = compute_urgency(sms, has_caps_flag=p.has_caps_flag, has_amounts=bool(p.amounts))
    short = sms[:55] + "..." if len(sms) > 55 else sms
    print(f"  Urgency:{urg:3d}/100  URLs:{len(p.urls)}  CAPS:{p.has_caps_flag} | {short}")

print()
print("=== NUMBER REPUTATION TEST ===")
numbers = ["+6281234567890", "+447700900000", "14045", None]
for num in numbers:
    r = check_number(num)
    print(f"  {str(num):20s} -> type={r['type']:15s} score={r['score']:3d}")

print()
print("=== BRAND DETECTOR TEST ===")
from tridetect.modules.web_phishing.brand_detector import BrandDetector
bd = BrandDetector()
typo_tests = [
    "http://bcaa.com/login",
    "http://g0pay-verify.ml",
    "http://shopee.co.id",
    "http://mandiri-bank.tk",
]
for url in typo_tests:
    match = bd.detect_typosquat(url)
    if match:
        print(f"  TYPOSQUAT: {match['typo_segment']} ~= {match['matched_alias']} (brand={match['brand']}, dist={match['edit_distance']})")
    else:
        print(f"  CLEAN: {url}")

print()
if all_ok:
    print("All web tests PASSED!")
else:
    print("Some tests FAILED - review above")
