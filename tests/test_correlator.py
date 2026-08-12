"""
AegisLog Correlator Tests

Tests grouping and time-window correlation of
authentication events.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent
from correlator import EventCorrelator


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


def test_events_are_correlated_by_ip_and_username():
    """Events from the same IP and user should be grouped."""

    correlator = EventCorrelator(
        window_seconds=60
    )

    start = datetime.now()

    events = [
        create_event(start),
        create_event(
            start + timedelta(seconds=10)
        ),
        create_event(
            start + timedelta(seconds=20)
        ),
    ]

    activities = correlator.correlate(events)

    assert len(activities) == 1

    activity = activities[0]

    assert activity.source_ip == "192.168.1.50"
    assert activity.target_user == "TEST_USER"
    assert activity.event_count == 3
    assert activity.failed_attempts == 3
    assert activity.successful_attempts == 0
    assert activity.duration_seconds == 20


def test_different_users_are_separate_activities():
    """Different usernames should not be merged."""

    correlator = EventCorrelator(
        window_seconds=60
    )

    start = datetime.now()

    events = [
        create_event(
            start,
            username="USER_A",
        ),
        create_event(
            start + timedelta(seconds=10),
            username="USER_B",
        ),
    ]

    activities = correlator.correlate(events)

    assert len(activities) == 2


def test_different_source_ips_are_separate_activities():
    """Different source IPs should not be merged."""

    correlator = EventCorrelator(
        window_seconds=60
    )

    start = datetime.now()

    events = [
        create_event(
            start,
            source_ip="192.168.1.50",
        ),
        create_event(
            start + timedelta(seconds=10),
            source_ip="192.168.1.60",
        ),
    ]

    activities = correlator.correlate(events)

    assert len(activities) == 2


def test_events_outside_window_create_separate_activities():
    """Events outside the correlation window should be separated."""

    correlator = EventCorrelator(
        window_seconds=60
    )

    start = datetime.now()

    events = [
        create_event(start),
        create_event(
            start + timedelta(seconds=30)
        ),
        create_event(
            start + timedelta(seconds=90)
        ),
    ]

    activities = correlator.correlate(events)

    assert len(activities) == 2

    assert activities[0].event_count == 2
    assert activities[1].event_count == 1


def test_success_after_failures_is_correlated():
    """Failures followed by a success should form one activity."""

    correlator = EventCorrelator(
        window_seconds=60
    )

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

    activities = correlator.correlate(events)

    assert len(activities) == 1

    activity = activities[0]

    assert activity.event_count == 4
    assert activity.failed_attempts == 3
    assert activity.successful_attempts == 1
    assert activity.duration_seconds == 25


def test_accepted_login_is_counted_as_success():
    """The legacy ACCEPTED status should also count as successful."""

    correlator = EventCorrelator(
        window_seconds=60
    )

    start = datetime.now()

    events = [
        create_event(
            start,
            status="FAILED",
        ),
        create_event(
            start + timedelta(seconds=10),
            status="ACCEPTED",
        ),
    ]

    activities = correlator.correlate(events)

    assert len(activities) == 1

    activity = activities[0]

    assert activity.failed_attempts == 1
    assert activity.successful_attempts == 1


def test_empty_event_list_returns_empty_result():
    """No events should produce no correlated activities."""

    correlator = EventCorrelator()

    activities = correlator.correlate([])

    assert activities == []