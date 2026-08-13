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


def test_failed_auth_events_can_be_queried(tmp_path):
    """Verify investigation queries return only failed events."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    failed_event = create_auth_event()

    successful_event = AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 31, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="SUCCESS",
        username="TEST_USER",
        source_ip="192.168.1.50",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Test Windows 4624 event",
    )

    storage.save_auth_event(failed_event)
    storage.save_auth_event(successful_event)

    failed_events = storage.get_failed_auth_events()

    assert len(failed_events) == 1
    assert failed_events[0]["status"] == "FAILED"
    assert failed_events[0]["username"] == "TEST_USER"
    assert failed_events[0]["source_ip"] == "192.168.1.50"


def test_auth_events_can_be_queried_by_ip(tmp_path):
    """Verify authentication events can be filtered by source IP."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    matching_event = create_auth_event()

    different_event = AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 32, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="FAILED",
        username="OTHER_USER",
        source_ip="10.0.0.25",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Test Windows 4625 event",
    )

    storage.save_auth_event(matching_event)
    storage.save_auth_event(different_event)

    events = storage.get_auth_events_by_ip(
        "192.168.1.50"
    )

    assert len(events) == 1
    assert events[0]["source_ip"] == "192.168.1.50"
    assert events[0]["username"] == "TEST_USER"


def test_auth_events_can_be_queried_by_username(tmp_path):
    """Verify authentication events can be filtered by username."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    matching_event = create_auth_event()

    different_event = AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 33, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="FAILED",
        username="OTHER_USER",
        source_ip="192.168.1.50",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Test Windows 4625 event",
    )

    storage.save_auth_event(matching_event)
    storage.save_auth_event(different_event)

    events = storage.get_auth_events_by_username(
        "TEST_USER"
    )

    assert len(events) == 1
    assert events[0]["username"] == "TEST_USER"
    assert events[0]["source_ip"] == "192.168.1.50"

def test_findings_can_be_queried_by_severity(tmp_path):
    """Verify security findings can be filtered by severity."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    high_finding = create_finding()

    low_finding = ThreatFinding(
        attack_type="Test Low Threat",
        severity="LOW",
        source_ip="10.0.0.25",
        target_user="OTHER_USER",
        attempts=1,
        service="Windows Authentication",
        first_seen=datetime(2026, 8, 12, 16, 40, 0),
        last_seen=datetime(2026, 8, 12, 16, 40, 1),
        recommendation="Monitor activity.",
        ip_classification="Private",
        event_count=1,
        failed_attempts=1,
        successful_attempts=0,
        duration_seconds=1.0,
    )

    storage.save_finding(high_finding)
    storage.save_finding(low_finding)

    findings = storage.get_findings_by_severity("HIGH")

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["attack_type"] == "Authentication Brute Force"

def test_auth_events_can_be_queried_by_time_range(tmp_path):
    """Verify authentication events can be filtered by time range."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    first_event = AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 0, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="FAILED",
        username="TEST_USER",
        source_ip="192.168.1.50",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="First event",
    )

    middle_event = AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 5, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="FAILED",
        username="TEST_USER",
        source_ip="192.168.1.50",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Middle event",
    )

    last_event = AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 10, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status="SUCCESS",
        username="TEST_USER",
        source_ip="192.168.1.50",
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Last event",
    )

    storage.save_auth_event(first_event)
    storage.save_auth_event(middle_event)
    storage.save_auth_event(last_event)

    events = storage.get_auth_events_between(
        datetime(2026, 8, 12, 16, 4, 0),
        datetime(2026, 8, 12, 16, 6, 0),
    )

    assert len(events) == 1
    assert events[0]["timestamp"] == "2026-08-12T16:05:00"
    assert events[0]["raw_log"] == "Middle event"

def test_findings_can_be_queried_by_ip(tmp_path):
    """Verify security findings can be filtered by source IP."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    matching_finding = create_finding()

    different_finding = ThreatFinding(
        attack_type="Password Spraying",
        severity="HIGH",
        source_ip="10.0.0.25",
        target_user="OTHER_USER",
        attempts=5,
        service="Windows Authentication",
        first_seen=datetime(2026, 8, 12, 16, 45, 0),
        last_seen=datetime(2026, 8, 12, 16, 45, 20),
        recommendation="Investigate source IP immediately.",
        ip_classification="Private",
        event_count=5,
        failed_attempts=5,
        successful_attempts=0,
        duration_seconds=20.0,
    )

    storage.save_finding(matching_finding)
    storage.save_finding(different_finding)

    findings = storage.get_findings_by_ip(
        "192.168.1.50"
    )

    assert len(findings) == 1
    assert findings[0]["source_ip"] == "192.168.1.50"
    assert findings[0]["attack_type"] == "Authentication Brute Force"



def test_findings_can_be_queried_by_username(tmp_path):
    """Verify security findings can be filtered by target username."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    matching_finding = create_finding()

    different_finding = ThreatFinding(
        attack_type="Password Spraying",
        severity="HIGH",
        source_ip="10.0.0.25",
        target_user="OTHER_USER",
        attempts=5,
        service="Windows Authentication",
        first_seen=datetime(2026, 8, 12, 16, 50, 0),
        last_seen=datetime(2026, 8, 12, 16, 50, 20),
        recommendation="Investigate source IP immediately.",
        ip_classification="Private",
        event_count=5,
        failed_attempts=5,
        successful_attempts=0,
        duration_seconds=20.0,
    )

    storage.save_finding(matching_finding)
    storage.save_finding(different_finding)

    findings = storage.get_findings_by_username(
        "TEST_USER"
    )

    assert len(findings) == 1
    assert findings[0]["target_user"] == "TEST_USER"
    assert findings[0]["attack_type"] == "Authentication Brute Force"

def test_finding_can_be_retrieved_by_id(tmp_path):
    """Verify a security finding can be retrieved by database ID."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    finding = create_finding()

    storage.save_finding(finding)

    findings = storage.get_findings()

    assert len(findings) == 1

    finding_id = findings[0]["id"]

    result = storage.get_finding_by_id(
        finding_id
    )

    assert result is not None
    assert result["id"] == finding_id
    assert result["attack_type"] == "Authentication Brute Force"
    assert result["severity"] == "HIGH"
    assert result["source_ip"] == "192.168.1.50"
    assert result["target_user"] == "TEST_USER"


def test_get_finding_by_id_returns_none_for_missing_id(tmp_path):
    """Verify missing finding IDs return None."""

    database = tmp_path / "test.db"

    storage = SecurityStorage(database)

    result = storage.get_finding_by_id(999)

    assert result is None