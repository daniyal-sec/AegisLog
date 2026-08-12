"""
AegisLog Storage Tests

Tests persistent SQLite storage for authentication
events and security findings.
"""

import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent, ThreatFinding
from storage import SecurityStorage


def create_auth_event():
    """Create a synthetic authentication event."""

    return AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 30, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="FAILED",
        username="TEST_USER",
        source_ip="192.168.1.50",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Test Windows 4625 event",
    )


def create_finding():
    """Create a synthetic security finding."""

    return ThreatFinding(
        attack_type="Authentication Brute Force",
        severity="HIGH",
        source_ip="192.168.1.50",
        target_user="TEST_USER",
        attempts=5,
        service="Windows Authentication",
        first_seen=datetime(2026, 8, 12, 16, 30, 0),
        last_seen=datetime(2026, 8, 12, 16, 30, 20),
        recommendation="Investigate source IP immediately.",
        ip_classification="Private",
        event_count=5,
        failed_attempts=5,
        successful_attempts=0,
        duration_seconds=20.0,
    )


def test_database_is_created(tmp_path):
    """Verify the SQLite database is created automatically."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    assert database.exists()
    assert storage.count_auth_events() == 0
    assert storage.count_findings() == 0


def test_auth_event_is_saved(tmp_path):
    """Verify authentication events can be persisted."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    event = create_auth_event()

    storage.save_auth_event(event)

    assert storage.count_auth_events() == 1


def test_multiple_auth_events_are_saved(tmp_path):
    """Verify multiple authentication events are persisted."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    storage.save_auth_event(create_auth_event())
    storage.save_auth_event(create_auth_event())
    storage.save_auth_event(create_auth_event())

    assert storage.count_auth_events() == 3


def test_threat_finding_is_saved(tmp_path):
    """Verify security findings can be persisted."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    finding = create_finding()

    storage.save_finding(finding)

    assert storage.count_findings() == 1


def test_multiple_findings_are_saved(tmp_path):
    """Verify multiple security findings are persisted."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    storage.save_finding(create_finding())
    storage.save_finding(create_finding())

    assert storage.count_findings() == 2


def test_events_and_findings_are_stored_separately(tmp_path):
    """Verify event and finding counts remain independent."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    storage.save_auth_event(create_auth_event())
    storage.save_auth_event(create_auth_event())

    storage.save_finding(create_finding())

    assert storage.count_auth_events() == 2
    assert storage.count_findings() == 1

def test_saved_auth_event_can_be_retrieved(tmp_path):
    """Verify stored authentication data can be read back."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    event = create_auth_event()

    storage.save_auth_event(event)

    events = storage.get_auth_events()

    assert len(events) == 1
    assert events[0]["status"] == "FAILED"
    assert events[0]["username"] == "TEST_USER"
    assert events[0]["source_ip"] == "192.168.1.50"
    assert events[0]["source_port"] == 445
    assert events[0]["hostname"] == "TestHost"


def test_saved_finding_can_be_retrieved(tmp_path):
    """Verify stored security finding data can be read back."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    finding = create_finding()

    storage.save_finding(finding)

    findings = storage.get_findings()

    assert len(findings) == 1
    assert findings[0]["attack_type"] == "Authentication Brute Force"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["target_user"] == "TEST_USER"
    assert findings[0]["attempts"] == 5
    assert findings[0]["failed_attempts"] == 5
    assert findings[0]["successful_attempts"] == 0
    assert findings[0]["duration_seconds"] == 20.0