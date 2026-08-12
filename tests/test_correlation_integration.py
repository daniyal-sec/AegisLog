"""
AegisLog Correlation Integration Tests

Verifies that correlated authentication activity
is correctly attached to ThreatFinding objects.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent
from correlator import EventCorrelator
from live_detector import LiveDetector


def create_event(
    timestamp,
    username="TEST_USER",
    source_ip="192.168.1.50",
    status="FAILED",
):
    """Create a synthetic authentication event."""

    return AuthEvent(
        timestamp=timestamp,
        hostname="TestHost",
        service="Windows Authentication",
        pid=0,
        status=status,
        username=username,
        source_ip=source_ip,
        source_port=0,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Synthetic authentication event",
    )


def test_correlator_and_detector_agree_on_attack_window():
    """
    Verify that the correlator groups five failures into one
    activity and LiveDetector identifies the same activity.
    """

    start = datetime.now()

    events = [
        create_event(
            start + timedelta(seconds=i * 5)
        )
        for i in range(5)
    ]

    correlator = EventCorrelator(
        window_seconds=60
    )

    activities = correlator.correlate(events)

    assert len(activities) == 1

    activity = activities[0]

    assert activity.event_count == 5
    assert activity.failed_attempts == 5
    assert activity.successful_attempts == 0
    assert activity.source_ip == "192.168.1.50"
    assert activity.target_user == "TEST_USER"

    detector = LiveDetector(
        window_seconds=60
    )

    findings = []

    for event in events:
        findings.extend(
            detector.add_event(event)
        )

    brute_force = [
        finding
        for finding in findings
        if finding.attack_type == "Authentication Brute Force"
    ]

    assert len(brute_force) == 1

    finding = brute_force[0]

    assert finding.source_ip == activity.source_ip
    assert finding.target_user == activity.target_user
    assert finding.attempts == activity.failed_attempts

    # New correlation fields.
    assert finding.event_count == 5
    assert finding.failed_attempts == 5
    assert finding.successful_attempts == 0
    assert finding.duration_seconds == 20


def test_failed_then_success_correlation_fields():
    """
    Verify that failed attempts followed by a successful
    authentication populate the correlation fields correctly.
    """

    start = datetime.now()

    events = [
        create_event(
            start,
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=5),
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=10),
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=15),
            status="SUCCESS",
        ),
    ]

    detector = LiveDetector(
        window_seconds=60
    )

    findings = []

    for event in events:
        findings.extend(
            detector.add_event(event)
        )

    successful_login = [
        finding
        for finding in findings
        if finding.attack_type
        == "Successful login after multiple failures"
    ]

    assert len(successful_login) == 1

    finding = successful_login[0]

    assert finding.event_count == 4
    assert finding.failed_attempts == 3
    assert finding.successful_attempts == 1
    assert finding.duration_seconds == 15


def test_correlation_fields_default_for_unmatched_finding():
    """
    Verify that ThreatFinding correlation fields have safe
    defaults when no matching correlated activity exists.
    """

    from models import ThreatFinding

    finding = ThreatFinding(
        attack_type="Test Finding",
        severity="LOW",
        source_ip="192.168.1.100",
        target_user="TEST_USER",
        attempts=1,
        service="Windows Authentication",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        recommendation="Test recommendation",
    )

    assert finding.event_count == 0
    assert finding.failed_attempts == 0
    assert finding.successful_attempts == 0
    assert finding.duration_seconds == 0.0