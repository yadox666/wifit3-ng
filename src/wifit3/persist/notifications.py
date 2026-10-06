from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_dir

from wifit3.persist.private_files import ensure_private_directory


NOTIFICATIONS_PATH = Path(user_data_dir("wifit3", appauthor=False)) / "notifications.sqlite3"
DISPLAY_LIMIT = 60
_RETAIN_MAX = 500


def _default_title(severity: str) -> str:
    normalized = (severity or "information").strip().casefold()
    if normalized == "info":
        normalized = "information"
    return normalized.replace("_", " ").replace("-", " ").title() or "Information"


class NotificationStoreError(RuntimeError):
    pass


@dataclass
class StoredNotification:
    id: str
    created_at: float
    title: str
    message: str
    severity: str
    read: bool


class NotificationStore:
    def __init__(self, path: Path = NOTIFICATIONS_PATH) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._open()

    def _open(self) -> None:
        try:
            ensure_private_directory(self.path.parent)
            connection = sqlite3.connect(
                self.path, timeout=5.0, check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            self._connection = connection
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    read INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS notifications_created_idx
                ON notifications(created_at DESC)
                """
            )
            connection.commit()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (OSError, sqlite3.Error) as exc:
            raise NotificationStoreError(
                f"Could not open notifications database: {exc}",
            ) from exc

    def append(
        self,
        message: str,
        *,
        title: str = "",
        severity: str = "information",
    ) -> StoredNotification:
        connection = self._connection
        if connection is None:
            raise NotificationStoreError("Notifications database is unavailable")
        title = (title or "").strip()
        message = (message or "").strip()
        severity = (severity or "information").strip().casefold()
        if not message and not title:
            message = "(empty notification)"
        if not title:
            title = _default_title(severity)
        row = StoredNotification(
            id=str(uuid.uuid4()),
            created_at=time.time(),
            title=title,
            message=message,
            severity=severity,
            read=False,
        )
        try:
            with self._lock, connection:
                connection.execute(
                    """
                    INSERT INTO notifications (
                        id, created_at, title, message, severity, read
                    ) VALUES (?, ?, ?, ?, ?, 0)
                    """,
                    (
                        row.id, row.created_at, row.title, row.message,
                        row.severity,
                    ),
                )
                self._prune(connection)
                connection.commit()
        except sqlite3.Error as exc:
            raise NotificationStoreError(f"Could not save notification: {exc}") from exc
        return row

    def _prune(self, connection: sqlite3.Connection) -> None:
        count = int(connection.execute("SELECT COUNT(*) FROM notifications").fetchone()[0])
        if count <= _RETAIN_MAX:
            return
        connection.execute(
            """
            DELETE FROM notifications
            WHERE id NOT IN (
                SELECT id FROM notifications
                ORDER BY created_at DESC
                LIMIT ?
            )
            """,
            (_RETAIN_MAX,),
        )

    def recent(self, limit: int = DISPLAY_LIMIT) -> list[StoredNotification]:
        connection = self._connection
        if connection is None:
            return []
        try:
            rows = connection.execute(
                """
                SELECT * FROM notifications
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
        except sqlite3.Error:
            return []
        return [self._row_to_notification(row) for row in rows]

    def unread_count(self) -> int:
        connection = self._connection
        if connection is None:
            return 0
        try:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM notifications WHERE read = 0",
                ).fetchone()[0]
            )
        except sqlite3.Error:
            return 0

    def mark_all_read(self) -> None:
        connection = self._connection
        if connection is None:
            return
        try:
            with self._lock, connection:
                connection.execute("UPDATE notifications SET read = 1 WHERE read = 0")
                connection.commit()
        except sqlite3.Error:
            pass

    @staticmethod
    def _row_to_notification(row: sqlite3.Row) -> StoredNotification:
        severity = str(row["severity"])
        return StoredNotification(
            id=str(row["id"]),
            created_at=float(row["created_at"]),
            title=str(row["title"]).strip() or _default_title(severity),
            message=str(row["message"]),
            severity=severity,
            read=bool(row["read"]),
        )

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
