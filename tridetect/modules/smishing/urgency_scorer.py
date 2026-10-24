"""Urgency score computation for SMS phishing detection."""

import re

URGENT_WORDS = [
    "urgent", "segera", "sekarang", "hari ini", "cepat",
    "menit", "jam", "detik", "batas waktu", "deadline",
    "immediately", "now", "today", "hurry",
]

THREAT_WORDS = [
    "diblokir", "ditutup", "dibekukan", "dihapus", "pemblokiran",
    "sanksi", "denda", "blokir", "freeze", "suspend", "blocked",
    "terminated", "nonaktif", "expired",
]

REWARD_WORDS = [
    "menang", "hadiah", "gratis", "bonus", "cashback",
    "voucher", "selamat", "terpilih", "beruntung", "free",
    "gift", "reward", "winner", "congratulations", "prize",
]

ACTION_WORDS = [
    "klik", "kunjungi", "transfer", "kirim", "verifikasi",
    "click", "visit", "confirm", "input", "masukkan",
    "send", "submit", "login", "signin",
]

_WEIGHTS = {
    "urgent": 15,
    "threat": 20,
    "reward": 12,
    "action": 8,
    "caps_bonus": 20,
    "multiple_exclamations": 5,
    "amount_present": 5,
}


def compute_urgency(text: str, has_caps_flag: bool = False, has_amounts: bool = False) -> int:
    """Return urgency score 0-100."""
    text_lower = text.lower()
    score = 0

    urgent_hits = sum(1 for w in URGENT_WORDS if w in text_lower)
    score += min(urgent_hits * _WEIGHTS["urgent"], 35)

    threat_hits = sum(1 for w in THREAT_WORDS if w in text_lower)
    score += min(threat_hits * _WEIGHTS["threat"], 40)

    reward_hits = sum(1 for w in REWARD_WORDS if w in text_lower)
    score += min(reward_hits * _WEIGHTS["reward"], 24)

    action_hits = sum(1 for w in ACTION_WORDS if w in text_lower)
    score += min(action_hits * _WEIGHTS["action"], 16)

    if has_caps_flag:
        score += _WEIGHTS["caps_bonus"]

    if re.search(r"!{2,}", text):
        score += _WEIGHTS["multiple_exclamations"]

    if has_amounts:
        score += _WEIGHTS["amount_present"]

    return min(score, 100)
