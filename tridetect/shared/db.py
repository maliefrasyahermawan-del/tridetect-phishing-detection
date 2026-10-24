import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from .logger import get_logger

logger = get_logger(__name__)

DB_PATH = Path(__file__).parent.parent.parent / "tridetect.db"


def init_db(db_path: Path = DB_PATH) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS classifications (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                module      TEXT    NOT NULL,
                input_hash  TEXT    NOT NULL,
                label       TEXT    NOT NULL,
                confidence  REAL    NOT NULL,
                reasons     TEXT,
                latency_ms  INTEGER
            )
            """
        )
        conn.commit()
    logger.info("DB initialised at %s", db_path)


@contextmanager
def get_conn(db_path: Path = DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def log_classification(
    module: str,
    input_hash: str,
    label: str,
    confidence: float,
    reasons: list[str],
    latency_ms: int,
    db_path: Path = DB_PATH,
) -> None:
    try:
        with get_conn(db_path) as conn:
            conn.execute(
                """
                INSERT INTO classifications
                    (timestamp, module, input_hash, label, confidence, reasons, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(),
                    module,
                    input_hash,
                    label,
                    confidence,
                    json.dumps(reasons),
                    latency_ms,
                ),
            )
            conn.commit()
    except Exception as exc:
        logger.warning("Failed to log classification: %s", exc)


def get_recent_classifications(limit: int = 100, db_path: Path = DB_PATH) -> list[dict]:
    try:
        with get_conn(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM classifications
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("Failed to fetch classifications: %s", exc)
        return []


def get_stats(db_path: Path = DB_PATH) -> dict:
    try:
        with get_conn(db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM classifications").fetchone()[0]
            by_label = conn.execute(
                "SELECT label, COUNT(*) FROM classifications GROUP BY label"
            ).fetchall()
            by_module = conn.execute(
                "SELECT module, COUNT(*) FROM classifications GROUP BY module"
            ).fetchall()
        return {
            "total": total,
            "by_label": dict(by_label),
            "by_module": dict(by_module),
        }
    except Exception:
        return {"total": 0, "by_label": {}, "by_module": {}}
