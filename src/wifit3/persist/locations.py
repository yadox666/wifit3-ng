from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

from platformdirs import user_data_dir

from wifit3.models.location import LocationFix, SignalPosition, distance_m
from wifit3.persist.private_files import ensure_private_directory


LOCATION_HISTORY_PATH = (
    Path(user_data_dir("wifit3", appauthor=False)) / "location_history.sqlite3"
)


class LocationStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = LOCATION_HISTORY_PATH if path is None else path
        self.errors: list[str] = []
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._cache: dict[tuple[str, str], list[SignalPosition]] = {}
        self._open()

    def _open(self) -> None:
        try:
            ensure_private_directory(self.path.parent)
            connection = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS positions (
                    entity_kind TEXT NOT NULL,
                    entity_id TEXT NOT NULL COLLATE NOCASE,
                    cluster_id INTEGER NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude_m REAL,
                    accuracy_m REAL NOT NULL,
                    observed_at REAL NOT NULL,
                    source TEXT NOT NULL,
                    rssi INTEGER,
                    PRIMARY KEY (entity_kind, entity_id, cluster_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS positions_entity_idx "
                "ON positions(entity_kind, entity_id)"
            )
            connection.commit()
            self._connection = connection
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (OSError, sqlite3.Error) as exc:
            self.errors.append(f"Could not open location history: {exc}")
            self.close()

    def observe(
        self,
        entity_kind: str,
        entity_id: str,
        fix: LocationFix | None,
        rssi: int | None,
        *,
        mobile: bool,
        movement_m: float,
        max_accuracy_m: float = 20.0,
    ) -> list[SignalPosition]:
        if fix is None or not fix.is_usable(max_accuracy_m=max_accuracy_m):
            return self.positions(entity_kind, entity_id)
        entity_id = entity_id.casefold()
        with self._lock:
            connection = self._connection
            if connection is None:
                return []
            key = (entity_kind, entity_id)
            positions = self._load_positions(connection, key)
            cluster_id = 0
            current = None
            if mobile and positions:
                candidate_distances = [
                    (distance_m(fix, position), index, position)
                    for index, position in enumerate(positions)
                ]
                distance, cluster_id, nearest = min(
                    candidate_distances, key=lambda item: item[0],
                )
                if distance <= movement_m:
                    current = nearest
                else:
                    cluster_id = len(positions)
            elif positions:
                current = positions[0]
            if current is not None and not _is_better(rssi, fix.accuracy_m, current):
                return list(positions)
            connection.execute(
                """
                INSERT INTO positions (
                    entity_kind, entity_id, cluster_id, latitude, longitude,
                    altitude_m, accuracy_m, observed_at, source, rssi
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_kind, entity_id, cluster_id) DO UPDATE SET
                    latitude = excluded.latitude,
                    longitude = excluded.longitude,
                    altitude_m = excluded.altitude_m,
                    accuracy_m = excluded.accuracy_m,
                    observed_at = excluded.observed_at,
                    source = excluded.source,
                    rssi = excluded.rssi
                """,
                (
                    entity_kind, entity_id, cluster_id, fix.latitude, fix.longitude,
                    fix.altitude_m, fix.accuracy_m, fix.observed_at, fix.source, rssi,
                ),
            )
            connection.commit()
            updated = SignalPosition(
                fix.latitude, fix.longitude, fix.altitude_m, fix.accuracy_m,
                fix.observed_at, fix.source, rssi,
            )
            if cluster_id == len(positions):
                positions.append(updated)
            else:
                positions[cluster_id] = updated
            return list(positions)

    def positions(self, entity_kind: str, entity_id: str) -> list[SignalPosition]:
        with self._lock:
            connection = self._connection
            if connection is None:
                return []
            return list(self._load_positions(
                connection, (entity_kind, entity_id.casefold()),
            ))

    def positions_for_kind(
        self, entity_kind: str,
    ) -> dict[str, list[SignalPosition]]:
        with self._lock:
            connection = self._connection
            if connection is None:
                return {}
            rows = connection.execute(
                """
                SELECT * FROM positions
                WHERE entity_kind = ?
                ORDER BY entity_id, cluster_id
                """,
                (entity_kind,),
            ).fetchall()
            grouped: dict[str, list[SignalPosition]] = {}
            for row in rows:
                grouped.setdefault(str(row["entity_id"]), []).append(_position(row))
            return grouped

    def _load_positions(
        self,
        connection: sqlite3.Connection,
        key: tuple[str, str],
    ) -> list[SignalPosition]:
        positions = self._cache.get(key)
        if positions is not None:
            return positions
        rows = connection.execute(
            """
            SELECT * FROM positions
            WHERE entity_kind = ? AND entity_id = ?
            ORDER BY cluster_id
            """,
            key,
        ).fetchall()
        positions = [_position(row) for row in rows]
        self._cache[key] = positions
        return positions

    def close(self) -> None:
        with self._lock:
            connection, self._connection = self._connection, None
            if connection is not None:
                connection.close()


def _position(row: sqlite3.Row) -> SignalPosition:
    return SignalPosition(
        latitude=float(row["latitude"]),
        longitude=float(row["longitude"]),
        altitude_m=float(row["altitude_m"]) if row["altitude_m"] is not None else None,
        accuracy_m=float(row["accuracy_m"]),
        observed_at=float(row["observed_at"]),
        source=str(row["source"]),
        rssi=int(row["rssi"]) if row["rssi"] is not None else None,
    )


def _is_better(rssi: int | None, accuracy_m: float, current: SignalPosition) -> bool:
    current_rssi = current.rssi
    if current_rssi is None:
        return rssi is not None or accuracy_m < current.accuracy_m
    if rssi is None:
        return False
    return rssi > current_rssi or (
        rssi == current_rssi and accuracy_m < current.accuracy_m
    )
