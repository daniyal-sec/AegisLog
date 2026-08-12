"""
AegisLog SQLite Storage

Provides persistent storage for normalized authentication
events and detected security findings.
"""

import sqlite3
from pathlib import Path

from models import AuthEvent, ThreatFinding


class SecurityStorage:
    """Persistent SQLite storage for AegisLog security data."""

    def __init__(self, database_path="data/aegislog.db"):
        self.database_path = Path(database_path)

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(self):
        """Create a new SQLite connection."""

        return sqlite3.connect(
            self.database_path
        )

    def _initialize_database(self):
        """Create the required database tables."""

        with self._connect() as connection:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    service TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    username TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    invalid_user INTEGER NOT NULL,
                    raw_log TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_user TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    ip_classification TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    failed_attempts INTEGER NOT NULL,
                    successful_attempts INTEGER NOT NULL,
                    duration_seconds REAL NOT NULL
                )
                """
            )

    def save_auth_event(self, event: AuthEvent):
        """Persist a normalized authentication event."""

        with self._connect() as connection:

            connection.execute(
                """
                INSERT INTO auth_events (
                    timestamp,
                    hostname,
                    service,
                    pid,
                    status,
                    username,
                    source_ip,
                    source_port,
                    protocol,
                    invalid_user,
                    raw_log
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    event.hostname,
                    event.service,
                    event.pid,
                    event.status,
                    event.username,
                    event.source_ip,
                    event.source_port,
                    event.protocol,
                    int(event.invalid_user),
                    event.raw_log,
                ),
            )

    def save_finding(self, finding: ThreatFinding):
        """Persist a detected security finding."""

        with self._connect() as connection:

            connection.execute(
                """
                INSERT INTO threat_findings (
                    attack_type,
                    severity,
                    source_ip,
                    target_user,
                    attempts,
                    service,
                    first_seen,
                    last_seen,
                    recommendation,
                    ip_classification,
                    event_count,
                    failed_attempts,
                    successful_attempts,
                    duration_seconds
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.attack_type,
                    finding.severity,
                    finding.source_ip,
                    finding.target_user,
                    finding.attempts,
                    finding.service,
                    finding.first_seen.isoformat(),
                    finding.last_seen.isoformat(),
                    finding.recommendation,
                    finding.ip_classification,
                    finding.event_count,
                    finding.failed_attempts,
                    finding.successful_attempts,
                    finding.duration_seconds,
                ),
            )

    def count_auth_events(self) -> int:
        """Return the number of stored authentication events."""

        with self._connect() as connection:

            result = connection.execute(
                "SELECT COUNT(*) FROM auth_events"
            ).fetchone()

            return result[0]

    def count_findings(self) -> int:
        """Return the number of stored security findings."""

        with self._connect() as connection:

            result = connection.execute(
                "SELECT COUNT(*) FROM threat_findings"
            ).fetchone()

            return result[0]

    def get_auth_events(self) -> list[dict]:
        """Return all stored authentication events."""

        with self._connect() as connection:

            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    hostname,
                    service,
                    pid,
                    status,
                    username,
                    source_ip,
                    source_port,
                    protocol,
                    invalid_user,
                    raw_log
                FROM auth_events
                ORDER BY id ASC
                """
            ).fetchall()

            return [dict(row) for row in rows]

    def get_findings(self) -> list[dict]:
        """Return all stored security findings."""

        with self._connect() as connection:

            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    id,
                    attack_type,
                    severity,
                    source_ip,
                    target_user,
                    attempts,
                    service,
                    first_seen,
                    last_seen,
                    recommendation,
                    ip_classification,
                    event_count,
                    failed_attempts,
                    successful_attempts,
                    duration_seconds
                FROM threat_findings
                ORDER BY id ASC
                """
            ).fetchall()

            return [dict(row) for row in rows]