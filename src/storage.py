"""
AegisLog SQLite Storage

Provides persistent storage for normalized authentication
events and detected security findings.
"""

import sqlite3
from contextlib import contextmanager
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

    @contextmanager
    def _connect(self):
        """
        Context manager that opens a SQLite connection, yields it, commits
        or rolls back the transaction on exit, and always closes the
        connection.

        Usage (unchanged at all call sites)::

            with self._connect() as connection:
                connection.execute(...)

        The sqlite3 built-in context manager only manages transactions
        (commit/rollback) and does NOT close the connection — leaving it
        open until garbage-collected and causing ResourceWarning on Python
        3.12+.  This wrapper adds the missing close() call.
        """
        connection = sqlite3.connect(self.database_path)
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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

    def get_failed_auth_events(self) -> list[dict]:
        """Return stored authentication events with FAILED status."""

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
                WHERE status = ?
                ORDER BY id ASC
                """,
                ("FAILED",),
            ).fetchall()

            return [dict(row) for row in rows]

    def get_auth_events_by_ip(
        self,
        source_ip: str,
    ) -> list[dict]:
        """Return authentication events from a specific source IP."""

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
                WHERE source_ip = ?
                ORDER BY id ASC
                """,
                (source_ip,),
            ).fetchall()

            return [dict(row) for row in rows]

    def get_auth_events_by_username(
        self,
        username: str,
    ) -> list[dict]:
        """Return authentication events for a specific username."""

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
                WHERE username = ?
                ORDER BY id ASC
                """,
                (username,),
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

    def get_findings_by_severity(
        self,
        severity: str,
    ) -> list[dict]:
        """Return security findings with a specific severity."""

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
                WHERE severity = ?
                ORDER BY id ASC
                """,
                (severity,),
            ).fetchall()

            return [dict(row) for row in rows]

    def get_findings_by_ip(
        self,
        source_ip: str,
    ) -> list[dict]:
        """Return security findings from a specific source IP."""

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
                WHERE source_ip = ?
                ORDER BY id ASC
                """,
                (source_ip,),
            ).fetchall()

            return [dict(row) for row in rows]

    def get_findings_by_username(
        self,
        username: str,
    ) -> list[dict]:
        """Return security findings for a specific target user."""

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
                WHERE target_user = ?
                ORDER BY id ASC
                """,
                (username,),
            ).fetchall()

            return [dict(row) for row in rows]

    

    def get_auth_events_between(
        self,
        start_time,
        end_time,
    ) -> list[dict]:
        """Return authentication events within a time range."""

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
                    WHERE timestamp >= ?
                AND timestamp <= ?
                ORDER BY timestamp ASC
                """,
                (
                    start_time.isoformat(),
                    end_time.isoformat(),
                ),
            ).fetchall()

            return [dict(row) for row in rows]




    def get_finding_by_id(self, finding_id: int):
        """Return a single security finding by ID."""

        with self._connect() as connection:

            connection.row_factory = sqlite3.Row

            row = connection.execute(
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
                WHERE id = ?
                """,
                (finding_id,),
            ).fetchone()

            if row is None:
                return None

            return dict(row)
