#!/usr/bin/env python3
"""Quick smoke test for Phase 1 modules."""
import sys
sys.path.insert(0, ".")

print("=== WEB PHISHING TEST ===")
from tridetect.modules.web_phishing.classifier import WebPhishingClassifier
clf = WebPhishingClassifier()

tests = [
    ("http://g0pay-verify.tk/check", False),
    ("http://192.168.1.1/login", False),
    ("http://mandiri-secure.xyz/login", False),
    ("https://www.tokopedia.com", False),
    ("https://shopee.co.id", False),
]

for url, check_ssl in tests:
    r = clf.classify(url, check_ssl=check_ssl)
    print(f"  [{r['label']:10s}] {r['confidence']:.1%} | {url}")
    if r.get("brand_match"):
        print(f"           Brand typosquat: {r['brand_match']}")

print()
print("=== SMISHING TEST ===")
from tridetect.modules.smishing.classifier import SmishingClassifier
clf2 = SmishingClassifier()

sms_tests = [
    "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: bit.ly/gopayverify",
    "Selamat! Anda memenangkan hadiah Rp 50.000.000 dari BCA. Klaim: jne-tracking.ml/id",
    "[BCA] Kode OTP Anda adalah: 843921. Berlaku 5 menit. Jangan bagikan kode ini kepada siapapun.",
    "Halo, meeting besok jam 09.00 WIB di ruang rapat lantai 3.",
]

for sms in sms_tests:
    r = clf2.classify(sms)
    short = sms[:60] + "..." if len(sms) > 60 else sms
    print(f"  [{r['label']:10s}] {r['confidence']:.1%} urgency={r['urgency_score']:3d} | {short}")

print()
print("=== PREPROCESSOR TEST ===")
from tridetect.modules.smishing.preprocessor import preprocess
text = "AKUN GOPAY ANDA DIBEKUKAN! Klik http://gopay-verify.tk Rp 50.000"
result = preprocess(text)
print(f"  URLs: {result.urls}")
print(f"  Amounts: {result.amounts}")
print(f"  CAPS flag: {result.has_caps_flag} ({result.caps_ratio:.0%} uppercase)")
print(f"  Language: {result.language_hint}")

print()
print("All smoke tests passed!")
