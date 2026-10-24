"""25+ lexical URL features for phishing detection."""

import re
import urllib.parse
from typing import Dict

import tldextract


_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom free TLDs - heavily abused
    ".xyz", ".top", ".click", ".loan", ".work",
    ".pw", ".cc", ".info", ".biz",
}

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "tiny.cc",
    "cutt.ly", "rb.gy", "shorte.st", "linktr.ee",
}

_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

_AT_SIGN_RE = re.compile(r"@")
_DOUBLE_SLASH_RE = re.compile(r"//")
_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")
_PORT_RE = re.compile(r":\d+")
_BRAND_WORDS = [
    "secure", "login", "verify", "account", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "google", "microsoft",
    "bca", "mandiri", "bni", "bri", "gopay", "ovo", "dana",
    "shopee", "tokopedia", "lazada",
]


def extract_features(url: str) -> Dict[str, float]:
    url = url.strip()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    extracted = tldextract.extract(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url

    features: Dict[str, float] = {}

    # ── Length features ──
    features["url_length"] = len(full_url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # ── Count features ──
    features["dot_count"] = hostname.count(".")
    features["hyphen_count"] = full_url.count("-")
    features["slash_count"] = full_url.count("/")
    features["at_sign"] = 1.0 if _AT_SIGN_RE.search(full_url) else 0.0
    features["double_slash_redirect"] = 1.0 if full_url.count("//") > 1 else 0.0
    features["hex_encoding"] = 1.0 if _HEX_RE.search(full_url) else 0.0
    features["has_port"] = 1.0 if _PORT_RE.search(hostname) else 0.0
    features["digit_ratio"] = (
        sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    )
    features["subdomain_count"] = len(extracted.subdomain.split(".")) if extracted.subdomain else 0

    # ── TLD / scheme ──
    tld = f".{extracted.suffix}" if extracted.suffix else ""
    features["suspicious_tld"] = 1.0 if tld.lower() in _SUSPICIOUS_TLDS else 0.0
    features["is_https"] = 1.0 if parsed.scheme == "https" else 0.0

    # ── IP address ──
    features["is_ip_address"] = 1.0 if _IP_PATTERN.match(hostname) else 0.0

    # ── URL shortener ──
    features["is_shortener"] = 1.0 if hostname.lower() in _SHORTENERS else 0.0

    # ── Brand words in URL ──
    url_lower = full_url.lower()
    features["brand_word_count"] = sum(w in url_lower for w in _BRAND_WORDS)

    # ── Suspicious patterns ──
    features["has_login_path"] = 1.0 if any(
        kw in path.lower() for kw in ["login", "signin", "verify", "auth"]
    ) else 0.0
    features["has_double_extension"] = 1.0 if re.search(
        r"\.(php|html|htm)\?|\.(exe|zip|rar)$", path.lower()
    ) else 0.0
    features["query_key_count"] = len(urllib.parse.parse_qs(query))
    features["has_redirect_param"] = 1.0 if any(
        k in ("redirect", "url", "next", "return", "goto")
        for k in urllib.parse.parse_qs(query)
    ) else 0.0

    # ── Domain age proxy (very new domain heuristic via random-looking TLD) ──
    domain_name = extracted.domain or ""
    features["domain_has_numbers"] = 1.0 if re.search(r"\d", domain_name) else 0.0
    features["domain_length"] = len(domain_name)
    features["excessive_subdomains"] = 1.0 if features["subdomain_count"] >= 3 else 0.0
    features["long_url"] = 1.0 if features["url_length"] > 100 else 0.0
    features["many_hyphens"] = 1.0 if features["hyphen_count"] >= 4 else 0.0

    return features


FEATURE_NAMES = list(extract_features("https://example.com").keys())
