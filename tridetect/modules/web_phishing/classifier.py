"""Web phishing classifier: Random Forest + XGBoost ensemble with rule fallback."""

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from tridetect.modules.web_phishing.brand_detector import BrandDetector
from tridetect.modules.web_phishing.features import extract_features
from tridetect.modules.web_phishing.ssl_checker import check_ssl
from tridetect.shared.logger import get_logger

logger = get_logger(__name__)

_MODEL_DIR = Path(__file__).parent.parent.parent.parent / "models_pretrained" / "web_rf"


def _rule_based_score(features: Dict[str, float]) -> float:
    """Heuristic score 0.0-1.0 (higher = more suspicious) when no model loaded."""
    score = 0.0

    # Strong individual signals
    if features.get("is_ip_address"):
        score += 0.55  # IP address in URL is a very strong indicator
    if features.get("at_sign"):
        score += 0.55  # @ sign tricks browsers
    if features.get("suspicious_tld"):
        score += 0.45  # Free TLDs heavily abused by phishers
    if features.get("is_shortener"):
        score += 0.35  # URL shortener hides destination
    if features.get("double_slash_redirect"):
        score += 0.30
    if features.get("hex_encoding"):
        score += 0.25
    if features.get("has_double_extension"):
        score += 0.35
    if features.get("has_port"):
        score += 0.20

    # Additive moderate signals
    if features.get("excessive_subdomains"):
        score += 0.20
    if features.get("has_login_path"):
        score += 0.15
    if features.get("many_hyphens"):
        score += 0.15
    if features.get("long_url"):
        score += 0.10
    if features.get("has_redirect_param"):
        score += 0.10
    if features.get("brand_word_count", 0) >= 2:
        score += 0.20
    if features.get("digit_ratio", 0) > 0.3:
        score += 0.10
    if features.get("url_length", 0) > 150:
        score += 0.10

    return min(score, 1.0)


class WebPhishingClassifier:
    def __init__(self):
        self._rf = None
        self._xgb = None
        self._brand_detector = BrandDetector()
        self._try_load_models()

    def _try_load_models(self) -> None:
        try:
            import joblib

            rf_path = _MODEL_DIR / "rf_model.pkl"
            xgb_path = _MODEL_DIR / "xgb_model.pkl"

            if rf_path.exists():
                self._rf = joblib.load(rf_path)
                logger.info("Loaded RF model from %s", rf_path)
            if xgb_path.exists():
                self._xgb = joblib.load(xgb_path)
                logger.info("Loaded XGB model from %s", xgb_path)
        except ImportError:
            logger.warning("joblib not installed, using rule-based fallback")
        except Exception as exc:
            logger.warning("Could not load models: %s — using rule-based fallback", exc)

    def _ml_score(self, features: Dict[str, float]) -> Optional[float]:
        """Return ensemble probability if models loaded, else None."""
        if self._rf is None and self._xgb is None:
            return None

        import numpy as np
        from tridetect.modules.web_phishing.features import FEATURE_NAMES

        vec = np.array([[features.get(k, 0.0) for k in FEATURE_NAMES]])
        scores = []
        if self._rf is not None:
            scores.append(self._rf.predict_proba(vec)[0][1])
        if self._xgb is not None:
            scores.append(self._xgb.predict_proba(vec)[0][1])
        return float(sum(scores) / len(scores))

    def classify(
        self,
        url: str,
        check_ssl: bool = True,
        check_brand: bool = True,
    ) -> Dict[str, Any]:
        url = url.strip()
        features = extract_features(url)
        reasons: list[str] = []

        # ── ML or rule-based classifier score ──
        ml_score = self._ml_score(features)
        classifier_score = ml_score if ml_score is not None else _rule_based_score(features)
        if ml_score is None:
            reasons.append("Rule-based classifier (no trained model)")

        # ── Brand typosquat detection ──
        brand_score = 0.0
        brand_match = None
        if check_brand:
            match = self._brand_detector.detect_typosquat(url)
            if match:
                brand_match = match["brand"]
                brand_score = 0.7
                reasons.append(
                    f"Typosquat of brand '{match['brand']}': "
                    f"'{match['typo_segment']}' ~= '{match['matched_alias']}' "
                    f"(edit distance {match['edit_distance']})"
                )

        # ── SSL check ──
        ssl_score = 0.0
        ssl_valid = None
        if check_ssl:
            ssl_result = check_ssl(url)
            ssl_valid = ssl_result["valid"]
            for anomaly in ssl_result["anomalies"]:
                reasons.append(f"SSL: {anomaly}")
            ssl_score = 0.6 if ssl_result["anomalies"] else 0.0

        # ── Feature-based reasons ──
        if features.get("is_ip_address"):
            reasons.append("IP address used instead of domain name")
        if features.get("suspicious_tld"):
            reasons.append("Suspicious free TLD (often abused by phishers)")
        if features.get("is_shortener"):
            reasons.append("URL shortener detected (hides destination)")
        if features.get("at_sign"):
            reasons.append("@ sign in URL (browser interprets text before @ as credentials)")
        if features.get("hex_encoding"):
            reasons.append("Hex/percent encoding in URL (obfuscation)")
        if features.get("excessive_subdomains"):
            reasons.append("Excessive subdomains (impersonation pattern)")
        if features.get("brand_word_count", 0) >= 2:
            reasons.append("Multiple brand keywords in URL (impersonation)")

        # ── Weighted aggregate ──
        aggregate = (
            classifier_score * 0.50
            + brand_score * 0.30
            + ssl_score * 0.20
        )

        # Combination boosting: multiple strong signals compound
        if brand_score > 0 and classifier_score >= 0.40:
            # Brand typosquat on a suspicious domain → strong indicator
            aggregate = min(aggregate + 0.25, 1.0)
        if features.get("is_ip_address") and not features.get("is_https"):
            aggregate = min(aggregate + 0.20, 1.0)

        aggregate = min(aggregate, 1.0)

        if aggregate >= 0.55:
            label = "malicious"
        elif aggregate >= 0.28:
            label = "suspicious"
        else:
            label = "safe"

        return {
            "label": label,
            "confidence": round(aggregate, 4),
            "reasons": reasons if reasons else ["No anomalies detected"],
            "brand_match": brand_match,
            "ssl_valid": ssl_valid,
        }
