"""Smishing classifier: IndoBERT fine-tuned + rule-based fallback."""

from pathlib import Path
from typing import Any, Dict, Optional

from tridetect.modules.smishing.number_reputation import check_number
from tridetect.modules.smishing.preprocessor import preprocess
from tridetect.modules.smishing.urgency_scorer import compute_urgency
from tridetect.shared.logger import get_logger

logger = get_logger(__name__)

_MODEL_DIR = Path(__file__).parent.parent.parent.parent / "models_pretrained" / "smishing_indobert"
_BASE_MODEL = "indolem/indobert-base-uncased"
_FALLBACK_MODEL = "distilbert-base-multilingual-cased"

# Keywords that strongly indicate smishing in Indonesian context
_PHISHING_KEYWORDS = {
    "dibekukan", "diblokir", "ditutup", "verifikasi", "verifikasi akun",
    "klik link", "segera konfirmasi", "akun anda", "rekening anda",
    "kami informasikan", "pemenang", "hadiah", "jutaan rupiah",
    "terima hadiah", "klaim hadiah", "klik sekarang", "jangan abaikan",
    "urgent", "segera", "gagal kirim", "pemblokiran",
    "anda terpilih", "selamat anda", "kode otp anda",
}

_SAFE_KEYWORDS = {
    "kode otp anda adalah", "kode verifikasi", "jangan bagikan otp",
    "transfer berhasil", "saldo anda", "notifikasi resmi",
}


def _rule_score(text_lower: str) -> float:
    phishing_hits = sum(1 for kw in _PHISHING_KEYWORDS if kw in text_lower)
    safe_hits = sum(1 for kw in _SAFE_KEYWORDS if kw in text_lower)

    # OTP messages are almost always legitimate
    if "otp" in text_lower and "jangan bagikan" in text_lower:
        return 0.05

    score = min(phishing_hits * 0.15, 0.90)
    score = max(score - safe_hits * 0.15, 0.0)
    return score


class SmishingClassifier:
    def __init__(self):
        self._pipeline = None
        self._try_load_model()

    def _try_load_model(self) -> None:
        model_path = _MODEL_DIR if _MODEL_DIR.exists() else _BASE_MODEL
        try:
            from transformers import pipeline as hf_pipeline

            logger.info("Loading IndoBERT smishing classifier from %s ...", model_path)
            self._pipeline = hf_pipeline(
                "text-classification",
                model=str(model_path),
                tokenizer=str(model_path),
                device=-1,  # CPU
                top_k=None,
            )
            logger.info("IndoBERT model loaded successfully")
        except Exception as exc:
            logger.warning(
                "Could not load IndoBERT (%s) — using rule-based fallback", exc
            )
            self._pipeline = None

    def _bert_score(self, text: str) -> Optional[float]:
        if self._pipeline is None:
            return None
        try:
            results = self._pipeline(text[:512])
            # Expect labels: LABEL_0 = benign, LABEL_1 = smishing
            if isinstance(results, list) and results:
                inner = results[0] if isinstance(results[0], list) else results
                label_map = {r["label"]: r["score"] for r in inner}
                # Fine-tuned model uses "smishing"/"benign" or LABEL_0/LABEL_1
                smishing_score = label_map.get("smishing") or label_map.get(
                    "LABEL_1", 0.0
                )
                return float(smishing_score)
        except Exception as exc:
            logger.warning("BERT inference error: %s", exc)
        return None

    def classify(
        self,
        text: str,
        sender_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        cleaned = preprocess(text)
        reasons: list[str] = []

        # ── Urgency score ──
        urgency = compute_urgency(
            text,
            has_caps_flag=cleaned.has_caps_flag,
            has_amounts=bool(cleaned.amounts),
        )

        # ── Sender reputation ──
        number_info = check_number(sender_number)
        number_score = number_info["score"] / 100.0

        if number_info["is_blocked"]:
            reasons.append(f"Sender number {sender_number} is in blocklist")
        elif number_info["type"] == "international":
            reasons.append("International sender number (suspicious for Indonesian banking SMS)")
        elif number_info["type"] == "shortcode" and number_info["score"] > 10:
            reasons.append("Suspicious short code sender")

        # ── URL extraction ──
        urls_found = cleaned.urls
        url_score = 0.0
        if urls_found:
            reasons.append(f"Contains {len(urls_found)} URL(s): {', '.join(urls_found[:3])}")
            suspicious_url_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"}
            for u in urls_found:
                if any(u.lower().endswith(tld) or f"{tld}/" in u.lower() for tld in suspicious_url_tlds):
                    reasons.append(f"Suspicious URL TLD detected: {u}")
                    url_score = max(url_score, 0.5)
                else:
                    url_score = max(url_score, 0.2)

        # ── NLP classification ──
        bert_score = self._bert_score(cleaned.cleaned)
        if bert_score is not None:
            classifier_score = bert_score
            reasons.append(f"IndoBERT confidence: {bert_score:.1%}")
        else:
            classifier_score = _rule_score(cleaned.cleaned)
            reasons.append("Rule-based NLP (IndoBERT not loaded)")

        # ── Urgency reasons ──
        if urgency >= 70:
            reasons.append(f"Very high urgency score ({urgency}/100) — high-pressure language detected")
        elif urgency >= 40:
            reasons.append(f"Elevated urgency score ({urgency}/100)")

        if cleaned.has_caps_flag:
            reasons.append(f"Excessive uppercase usage ({cleaned.caps_ratio:.0%} of letters)")
        if cleaned.amounts:
            reasons.append(f"Monetary amounts detected: {', '.join(cleaned.amounts[:3])}")

        # ── Aggregate score ──
        urgency_norm = urgency / 100.0
        aggregate = (
            classifier_score * 0.45
            + urgency_norm * 0.25
            + url_score * 0.15
            + number_score * 0.15
        )
        aggregate = min(aggregate, 1.0)

        if aggregate >= 0.60:
            label = "malicious"
        elif aggregate >= 0.30:
            label = "suspicious"
        else:
            label = "safe"

        return {
            "label": label,
            "confidence": round(aggregate, 4),
            "reasons": reasons if reasons else ["No phishing indicators detected"],
            "urls_found": urls_found,
            "urgency_score": urgency,
            "sender_reputation": number_info["type"],
        }
