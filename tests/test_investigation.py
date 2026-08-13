"""
AegisLog Investigation Console Tests

Tests the interactive investigation interface using
temporary SQLite databases and mocked user input.
"""

import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent, ThreatFinding
from investigation import InvestigationConsole


def create_auth_event(
    status="FAILED",
    username="TEST_USER",
    source_ip="192.168.1.50",
):
    """Create a synthetic authentication event."""

    return AuthEvent(
        timestamp=datetime(2026, 8, 12, 16, 0, 0),
        hostname="TestHost",
        service="Windows Authentication",
        pid=1234,
        status=status,
        username=username,
        source_ip=source_ip,
        source_port=445,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Synthetic Windows authentication event",
    )


def create_finding(
    severity="HIGH",
    source_ip="192.168.1.50",
    username="TEST_USER",
):
    """Create a synthetic security finding."""

    return ThreatFinding(
        attack_type="Authentication Brute Force",
        severity=severity,
        source_ip=source_ip,
        target_user=username,
        attempts=5,
        service="Windows Authentication",
        first_seen=datetime(2026, 8, 12, 16, 0, 0),
        last_seen=datetime(2026, 8, 12, 16, 0, 20),
        recommendation="Investigate source IP immediately.",
        ip_classification="Private",
        event_count=5,
        failed_attempts=5,
        successful_attempts=0,
        duration_seconds=20.0,
    )


def test_investigation_console_can_initialize(tmp_path):
    """Verify the investigation console initializes correctly."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    assert console.storage.database_path == database


def test_search_by_ip_returns_matching_events(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify IP investigation returns matching events."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    event = create_auth_event()

    console.storage.save_auth_event(event)

    monkeypatch.setattr(
        "builtins.input",
        lambda _: "192.168.1.50",
    )

    console.search_by_ip()

    output = capsys.readouterr().out

    assert "192.168.1.50" in output
    assert "TEST_USER" in output
    assert "FAILED" in output


def test_search_by_username_returns_matching_events(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify username investigation returns matching events."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    event = create_auth_event()

    console.storage.save_auth_event(event)

    monkeypatch.setattr(
        "builtins.input",
        lambda _: "TEST_USER",
    )

    console.search_by_username()

    output = capsys.readouterr().out

    assert "TEST_USER" in output
    assert "FAILED" in output
    assert "192.168.1.50" in output


def test_search_by_time_range_returns_matching_events(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify time-range investigation returns matching events."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    event = create_auth_event()

    console.storage.save_auth_event(event)

    inputs = iter(
        [
            "2026-08-12 15:59:00",
            "2026-08-12 16:01:00",
        ]
    )

    monkeypatch.setattr(
        "builtins.input",
        lambda _: next(inputs),
    )

    console.search_by_time_range()

    output = capsys.readouterr().out

    assert "TEST_USER" in output
    assert "FAILED" in output


def test_findings_by_severity_returns_matching_findings(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify severity investigation returns matching findings."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    finding = create_finding()

    console.storage.save_finding(finding)

    monkeypatch.setattr(
        "builtins.input",
        lambda _: "HIGH",
    )

    console.search_findings_by_severity()

    output = capsys.readouterr().out

    assert "Authentication Brute Force" in output
    assert "HIGH" in output
    assert "192.168.1.50" in output


def test_findings_by_username_returns_matching_findings(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify username investigation returns matching findings."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    finding = create_finding()

    console.storage.save_finding(finding)

    monkeypatch.setattr(
        "builtins.input",
        lambda _: "TEST_USER",
    )

    console.search_findings_by_username()

    output = capsys.readouterr().out

    assert "Authentication Brute Force" in output
    assert "TEST_USER" in output
    assert "HIGH" in output


def test_investigate_finding_shows_incident_timeline(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify finding investigation displays related events."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    finding = create_finding()

    console.storage.save_finding(finding)

    events = [
        create_auth_event(
            status="FAILED",
            username="TEST_USER",
            source_ip="192.168.1.50",
        ),
        create_auth_event(
            status="FAILED",
            username="TEST_USER",
            source_ip="192.168.1.50",
        ),
    ]

    for event in events:
        console.storage.save_auth_event(event)

    stored_findings = console.storage.get_findings()

    finding_id = stored_findings[0]["id"]

    monkeypatch.setattr(
        "builtins.input",
        lambda _: str(finding_id),
    )

    console.investigate_finding()

    output = capsys.readouterr().out

    assert "INCIDENT INVESTIGATION" in output
    assert "Authentication Brute Force" in output
    assert "HIGH" in output
    assert "192.168.1.50" in output
    assert "TEST_USER" in output
    assert "EVENT TIMELINE" in output
    assert "INVESTIGATION SUMMARY" in output
    assert "Recommendation" in output


def test_investigate_missing_finding_is_handled(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Verify investigating a nonexistent finding is handled safely."""

    database = tmp_path / "test.db"

    console = InvestigationConsole(database)

    monkeypatch.setattr(
        "builtins.input",
        lambda _: "999",
    )

    console.investigate_finding()

    output = capsys.readouterr().out

    assert "No finding found with ID 999." in output