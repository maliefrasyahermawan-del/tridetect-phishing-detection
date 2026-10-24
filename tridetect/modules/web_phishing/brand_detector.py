"""Brand typosquatting detection using Levenshtein distance."""

import json
from pathlib import Path
from typing import Optional

import Levenshtein
import tldextract

from tridetect.shared.logger import get_logger

logger = get_logger(__name__)

_BRANDS_FILE = Path(__file__).parent.parent.parent / "data" / "brands.json"

_THRESHOLD = 2  # edit distance threshold for typosquat match


class BrandDetector:
    def __init__(self, brands_file: Path = _BRANDS_FILE):
        self._brands: dict[str, list[str]] = {}
        self._load(brands_file)

    def _load(self, path: Path) -> None:
        if not path.exists():
            logger.warning("brands.json not found at %s — brand detection disabled", path)
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        # Expect: {"BCA": ["bca", "klikbca"], "Shopee": ["shopee", "shopee-id"], ...}
        self._brands = {brand: aliases for brand, aliases in data.items()}
        logger.info("Loaded %d brands for typosquat detection", len(self._brands))

    def detect_typosquat(self, url: str) -> Optional[dict]:
        """Return brand match info if typosquat detected, else None."""
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()
        subdomain = extracted.subdomain.lower()
        suffix = extracted.suffix.lower()

        # Collect all segments to check: dot-split + hyphen-split of domain
        raw_parts = [domain]
        if subdomain:
            raw_parts.extend(subdomain.split("."))

        candidates: set[str] = set()
        for part in raw_parts:
            candidates.add(part)
            # Also add hyphen-split segments (e.g. "g0pay-verify" → "g0pay", "verify")
            for seg in part.split("-"):
                if len(seg) >= 3:
                    candidates.add(seg)

        # Legitimate TLDs where exact-domain matches are probably real brands
        trusted_suffix = suffix in ("com", "co.id", "net", "org", "go.id", "ac.id", "id")

        # Phase 1: early-exit for legitimate exact domain matches on trusted TLDs.
        # If the registered domain exactly matches any brand alias on a trusted TLD,
        # it's the real brand — skip typosquat detection entirely.
        if trusted_suffix:
            for brand, aliases in self._brands.items():
                for alias in aliases:
                    if domain == alias.lower():
                        return None  # legitimate brand domain

        # Phase 2: check all candidate segments for typosquatting
        for part in sorted(candidates, key=len, reverse=True):  # longer segments first
            for brand, aliases in self._brands.items():
                for alias in aliases:
                    alias_lower = alias.lower()
                    dist = Levenshtein.distance(part, alias_lower)
                    if dist == 0:
                        # Exact match of a sub-segment (e.g. "gopay" in "gopay-verify.tk")
                        # or exact match on untrusted TLD → flag
                        return {
                            "brand": brand,
                            "matched_alias": alias,
                            "typo_segment": part,
                            "edit_distance": 0,
                        }
                    elif dist <= _THRESHOLD:
                        return {
                            "brand": brand,
                            "matched_alias": alias,
                            "typo_segment": part,
                            "edit_distance": dist,
                        }

        return None

    @property
    def brand_count(self) -> int:
        return len(self._brands)
