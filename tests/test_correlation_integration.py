"""
AegisLog Correlation Integration Tests

Verifies that correlated authentication activity
and the existing LiveDetector work correctly together.
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
    activity and the LiveDetector identifies the same activity
    as brute force.
    """

    start = datetime.now()

    events = [
        create_event(
            start + timedelta(seconds=i * 5)
        )
        for i in range(5)
    ]

    # Correlation layer.
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

    # Detection layer.
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


def test_failed_then_success_is_one_correlated_activity():
    """
    Verify that repeated failures followed by a successful
    authentication remain one correlated activity.
    """

    start = datetime.now()

    events = [
        create_event(
            start,
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=10),
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=20),
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=25),
            status="SUCCESS",
        ),
    ]

    correlator = EventCorrelator(
        window_seconds=60
    )

    activities = correlator.correlate(events)

    assert len(activities) == 1

    activity = activities[0]

    assert activity.event_count == 4
    assert activity.failed_attempts == 3
    assert activity.successful_attempts == 1
    assert activity.duration_seconds == 25


def test_separate_attack_windows_remain_separate():
    """
    Verify that activity separated by more than the
    correlation window is treated as separate activity.
    """

    start = datetime.now()

    events = [
        create_event(start),
        create_event(
            start + timedelta(seconds=10)
        ),
        create_event(
            start + timedelta(seconds=20)
        ),
        create_event(
            start + timedelta(seconds=100)
        ),
    ]

    correlator = EventCorrelator(
        window_seconds=60
    )

    activities = correlator.correlate(events)

    assert len(activities) == 2

    assert activities[0].event_count == 3
    assert activities[1].event_count == 1