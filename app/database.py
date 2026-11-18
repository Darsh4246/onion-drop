"""Database management for OnionDrop.

Stores upload metadata (UUID, sanitized original filename, file size, timestamp)
in SQLite. Absolutely no query/listing capabilities are exposed through the web API.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Create and configure a SQLite connection."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency and resilience
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path) -> None:
    """Initialize database tables and indexes."""
    with get_db_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_uuid TEXT NOT NULL UNIQUE,
                original_filename TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                content_type TEXT,
                uploaded_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_uploads_file_uuid ON uploads(file_uuid);
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_uploads_uploaded_at ON uploads(uploaded_at);
        """)
        conn.commit()


def record_upload(
    db_path: Path,
    file_uuid: str,
    original_filename: str,
    file_size_bytes: int,
    content_type: Optional[str] = None
) -> int:
    """Record an upload's metadata in the database."""
    now_utc = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO uploads (file_uuid, original_filename, file_size_bytes, content_type, uploaded_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (file_uuid, original_filename, file_size_bytes, content_type or "application/octet-stream", now_utc)
        )
        conn.commit()
        return cursor.lastrowid
