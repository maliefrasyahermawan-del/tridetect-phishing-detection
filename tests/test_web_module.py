"""Unit tests for Web Phishing module."""

import pytest

from tridetect.modules.web_phishing.features import extract_features


class TestFeatureExtraction:
    def test_ip_address_url(self):
        feats = extract_features("http://192.168.1.1/login")
        assert feats["is_ip_address"] == 1.0

    def test_https_scheme(self):
        feats = extract_features("https://google.com")
        assert feats["is_https"] == 1.0

    def test_http_scheme(self):
        feats = extract_features("http://google.com")
        assert feats["is_https"] == 0.0

    def test_suspicious_tld(self):
        feats = extract_features("http://example.tk/login")
        assert feats["suspicious_tld"] == 1.0

    def test_benign_tld(self):
        feats = extract_features("https://google.com")
        assert feats["suspicious_tld"] == 0.0

    def test_url_shortener(self):
        feats = extract_features("http://bit.ly/abc123")
        assert feats["is_shortener"] == 1.0

    def test_at_sign(self):
        feats = extract_features("http://phisher.com@legit.com/login")
        assert feats["at_sign"] == 1.0

    def test_hex_encoding(self):
        feats = extract_features("http://example.com/%61%62%63")
        assert feats["hex_encoding"] == 1.0

    def test_long_url(self):
        long_url = "https://example.com/" + "a" * 200
        feats = extract_features(long_url)
        assert feats["long_url"] == 1.0

    def test_normal_url(self):
        feats = extract_features("https://tokopedia.com")
        assert feats["is_ip_address"] == 0.0
        assert feats["suspicious_tld"] == 0.0
        assert feats["is_shortener"] == 0.0


class TestBrandDetector:
    def setup_method(self):
        from tridetect.modules.web_phishing.brand_detector import BrandDetector
        self.detector = BrandDetector()

    def test_detects_typosquat(self):
        result = self.detector.detect_typosquat("http://bcaa.com/login")
        # bcaa vs bca: edit distance 1
        assert result is not None
        assert result["brand"] == "BCA"

    def test_no_false_positive_on_real_domain(self):
        result = self.detector.detect_typosquat("https://bca.co.id")
        # exact match → not a typosquat
        assert result is None

    def test_detects_gopay_typo(self):
        result = self.detector.detect_typosquat("http://g0pay-verify.ml/check")
        assert result is not None
        assert result["brand"] == "GoPay"


class TestSSLChecker:
    def test_returns_dict(self):
        from tridetect.modules.web_phishing.ssl_checker import check_ssl
        result = check_ssl("https://example.com", timeout=2.0)
        assert "valid" in result
        assert "anomalies" in result
        assert isinstance(result["anomalies"], list)

    def test_http_url_flagged(self):
        from tridetect.modules.web_phishing.ssl_checker import check_ssl
        result = check_ssl("http://example.com")
        assert any("HTTP" in a or "plain" in a.lower() for a in result["anomalies"])


class TestWebClassifier:
    def setup_method(self):
        from tridetect.modules.web_phishing.classifier import WebPhishingClassifier
        self.clf = WebPhishingClassifier()

    def test_phishing_url_flagged(self):
        result = self.clf.classify("http://g0pay-verify.tk/check", check_ssl=False)
        assert result["label"] in ("suspicious", "malicious")
        assert result["confidence"] > 0.3

    def test_benign_url_safe(self):
        result = self.clf.classify("https://www.tokopedia.com", check_ssl=False, check_brand=False)
        assert result["label"] == "safe"

    def test_ip_url_flagged(self):
        result = self.clf.classify("http://192.168.0.1/login", check_ssl=False)
        assert result["label"] in ("suspicious", "malicious")

    def test_result_structure(self):
        result = self.clf.classify("https://google.com", check_ssl=False)
        assert "label" in result
        assert "confidence" in result
        assert "reasons" in result
        assert 0.0 <= result["confidence"] <= 1.0
