"""Unit tests for Smishing module."""

import pytest

from tridetect.modules.smishing.preprocessor import preprocess
from tridetect.modules.smishing.urgency_scorer import compute_urgency


class TestPreprocessor:
    def test_url_extraction(self):
        result = preprocess("Klik sekarang: http://bit.ly/abc123 untuk verifikasi")
        assert len(result.urls) >= 1
        assert any("bit.ly" in u for u in result.urls)

    def test_amount_extraction(self):
        result = preprocess("Anda memenangkan hadiah Rp 50.000.000")
        assert len(result.amounts) >= 1

    def test_caps_detection(self):
        result = preprocess("AKUN ANDA AKAN DIBEKUKAN SEGERA")
        assert result.has_caps_flag is True
        assert result.caps_ratio > 0.30

    def test_lowercase_normal(self):
        result = preprocess("Halo, ini pesan biasa tanpa ancaman.")
        assert result.has_caps_flag is False

    def test_slang_normalization(self):
        result = preprocess("gw mau kasih tau lo sesuatu")
        assert "saya" in result.cleaned
        assert "kamu" in result.cleaned

    def test_language_hint_id(self):
        result = preprocess("Segera klik link untuk verifikasi akun Anda")
        assert result.language_hint == "id"


class TestUrgencyScorer:
    def test_high_urgency_threat(self):
        score = compute_urgency("AKUN ANDA AKAN DIBEKUKAN SEGERA VERIFIKASI SEKARANG", has_caps_flag=True)
        assert score >= 50

    def test_reward_phishing(self):
        score = compute_urgency("Selamat Anda memenangkan hadiah gratis voucher cashback")
        assert score >= 30

    def test_otp_low_urgency(self):
        score = compute_urgency("Kode OTP Anda adalah 123456. Jangan bagikan ke siapapun.")
        assert score < 40

    def test_benign_low_score(self):
        score = compute_urgency("Halo, bagaimana kabar Anda hari ini?")
        assert score < 20

    def test_caps_bonus(self):
        score_with_caps = compute_urgency("SEGERA", has_caps_flag=True)
        score_no_caps = compute_urgency("segera", has_caps_flag=False)
        assert score_with_caps > score_no_caps


class TestNumberReputation:
    def test_none_number(self):
        from tridetect.modules.smishing.number_reputation import check_number
        result = check_number(None)
        assert result["is_blocked"] is False

    def test_indonesian_mobile(self):
        from tridetect.modules.smishing.number_reputation import check_number
        result = check_number("+6281234567890")
        assert result["country"] == "id"

    def test_international_number(self):
        from tridetect.modules.smishing.number_reputation import check_number
        result = check_number("+447700900000")
        assert result["country"] == "international"
        assert result["score"] > 10

    def test_shortcode(self):
        from tridetect.modules.smishing.number_reputation import check_number
        result = check_number("14045")
        assert result["type"] == "shortcode"


class TestSmishingClassifier:
    def setup_method(self):
        from tridetect.modules.smishing.classifier import SmishingClassifier
        self.clf = SmishingClassifier()

    def test_phishing_sms_flagged(self):
        sms = "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: g0pay-verify.tk/check"
        result = self.clf.classify(sms)
        assert result["label"] in ("suspicious", "malicious")

    def test_otp_safe(self):
        sms = "Kode OTP BCA Anda adalah 843921. Berlaku 5 menit. Jangan bagikan kode ini."
        result = self.clf.classify(sms)
        assert result["label"] in ("safe", "suspicious")

    def test_result_structure(self):
        result = self.clf.classify("Test pesan biasa")
        assert "label" in result
        assert "confidence" in result
        assert "reasons" in result
        assert "urls_found" in result
        assert "urgency_score" in result
        assert 0.0 <= result["confidence"] <= 1.0
        assert 0 <= result["urgency_score"] <= 100

    def test_url_detected_in_result(self):
        sms = "Klik di sini: http://bit.ly/xyz untuk klaim hadiah"
        result = self.clf.classify(sms)
        assert len(result["urls_found"]) >= 1
