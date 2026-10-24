"""Simple in-memory URL cache (TTL-based). Redis can replace this in production."""

import time
from threading import Lock
from typing import Any, Optional

from .logger import get_logger

logger = get_logger(__name__)

_DEFAULT_TTL = 3600  # 1 hour


class TTLCache:
    def __init__(self, ttl: int = _DEFAULT_TTL, max_size: int = 10_000):
        self._store: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl
        self._max_size = max_size
        self._lock = Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._store) >= self._max_size:
                self._evict()
            self._store[key] = (value, time.time() + self._ttl)

    def _evict(self) -> None:
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]
        if len(self._store) >= self._max_size and self._store:
            oldest = min(self._store, key=lambda k: self._store[k][1])
            del self._store[oldest]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


url_cache = TTLCache(ttl=_DEFAULT_TTL)
