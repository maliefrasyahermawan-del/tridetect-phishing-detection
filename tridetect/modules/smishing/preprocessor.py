"""SMS text preprocessing for Indonesian phishing detection."""

import re
from dataclasses import dataclass, field
from typing import Optional

_URL_PATTERN = re.compile(
    r"https?://[^\s]+"
    r"|www\.[^\s]+"
    r"|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?"
)

_AMOUNT_PATTERN = re.compile(r"Rp\.?\s?\d[\d.,]*", re.IGNORECASE)

_SLANG_MAP = {
    r"\bgw\b": "saya",
    r"\bgue\b": "saya",
    r"\baku\b": "saya",
    r"\blo\b": "kamu",
    r"\blu\b": "kamu",
    r"\bgak\b": "tidak",
    r"\bnggak\b": "tidak",
    r"\benggak\b": "tidak",
    r"\bga\b": "tidak",
    r"\butk\b": "untuk",
    r"\bsgr\b": "segera",
    r"\byg\b": "yang",
    r"\bkrn\b": "karena",
    r"\bdg\b": "dengan",
    r"\bdgn\b": "dengan",
    r"\btp\b": "tapi",
    r"\bttg\b": "tentang",
    r"\bblm\b": "belum",
    r"\bsdh\b": "sudah",
    r"\bsudh\b": "sudah",
    r"\bjgn\b": "jangan",
    r"\bhrs\b": "harus",
    r"\binfo\b": "informasi",
}


@dataclass
class CleanedText:
    original: str
    cleaned: str
    urls: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    has_caps_flag: bool = False
    caps_ratio: float = 0.0
    language_hint: str = "id"


def preprocess(text: str) -> CleanedText:
    original = text

    # Extract URLs before modifying text
    urls = _URL_PATTERN.findall(text)
    urls = list({u.rstrip(".,;)\"'") for u in urls})

    # Extract money amounts
    amounts = _AMOUNT_PATTERN.findall(text)

    # CAPS detection (before lowercasing)
    alpha_chars = [c for c in text if c.isalpha()]
    caps_ratio = (
        sum(c.isupper() for c in alpha_chars) / max(len(alpha_chars), 1)
    )
    has_caps_flag = caps_ratio > 0.30

    # Normalize whitespace
    cleaned = re.sub(r"\s+", " ", text).strip()

    # Lowercase (preserve original for caps detection already done)
    cleaned = cleaned.lower()

    # Normalize slang
    for pattern, replacement in _SLANG_MAP.items():
        cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)

    # Remove repeated punctuation (!!!! → !)
    cleaned = re.sub(r"([!?.]){2,}", r"\1", cleaned)

    # Language hint: check for Indonesian stopwords
    indonesian_markers = {"anda", "segera", "klik", "yang", "ini", "untuk", "tidak"}
    tokens = set(cleaned.split())
    language_hint = "id" if indonesian_markers.intersection(tokens) else "en"

    return CleanedText(
        original=original,
        cleaned=cleaned,
        urls=urls,
        amounts=amounts,
        has_caps_flag=has_caps_flag,
        caps_ratio=round(caps_ratio, 3),
        language_hint=language_hint,
    )
