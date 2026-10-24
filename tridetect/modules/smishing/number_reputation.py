"""Sender number reputation check against local blocklist."""

import json
import re
from pathlib import Path
from typing import Optional

from tridetect.shared.logger import get_logger

logger = get_logger(__name__)

_BLOCKLIST_FILE = Path(__file__).parent.parent.parent / "data" / "number_blocklist.json"

_INTERNATIONAL_PREFIX = re.compile(r"^\+(?!62)")  # international, not Indonesia
_SHORT_CODE_PATTERN = re.compile(r"^\d{4,6}$")
_INDONESIA_PREFIX = re.compile(r"^(\+62|62|0)(8\d{8,11})$")


def _load_blocklist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return set(data.get("blocked_numbers", []))


_BLOCKLIST: set[str] = set()


def _ensure_loaded() -> None:
    global _BLOCKLIST
    if not _BLOCKLIST:
        _BLOCKLIST = _load_blocklist(_BLOCKLIST_FILE)
        logger.info("Loaded %d blocked numbers", len(_BLOCKLIST))


def _normalize(number: str) -> str:
    return re.sub(r"[\s\-\(\)]", "", number)


def check_number(number: Optional[str]) -> dict:
    if not number:
        return {"is_blocked": False, "country": "unknown", "type": "unknown", "score": 0}

    _ensure_loaded()
    normalized = _normalize(number)

    if normalized in _BLOCKLIST:
        return {
            "is_blocked": True,
            "country": "unknown",
            "type": "blocklisted",
            "score": 80,
        }

    if _SHORT_CODE_PATTERN.match(normalized):
        is_suspicious = len(normalized) <= 5
        return {
            "is_blocked": False,
            "country": "id",
            "type": "shortcode",
            "score": 30 if is_suspicious else 10,
        }

    if _INTERNATIONAL_PREFIX.match(normalized):
        return {
            "is_blocked": False,
            "country": "international",
            "type": "international",
            "score": 40,
        }

    if _INDONESIA_PREFIX.match(normalized):
        return {
            "is_blocked": False,
            "country": "id",
            "type": "mobile",
            "score": 5,
        }

    return {"is_blocked": False, "country": "unknown", "type": "unknown", "score": 15}
