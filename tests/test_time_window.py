"""
AegisLog Time-Window Tests

Tests the rolling event buffer used by LiveDetector.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent
from live_detector import LiveDetector


def create_event(timestamp, username="TEST_USER"):
    """Create a synthetic authentication event."""

    return AuthEvent(
        timestamp=timestamp,
        hostname="TestHost",
        service="Windows Authentication",
        pid=0,
        status="FAILED",
        username=username,
        source_ip="192.168.1.50",
        source_port=0,
        protocol="Windows Security",
        invalid_user=False,
        raw_log="Synthetic authentication event",
    )


def test_old_events_are_removed_from_window():
    """
    Events older than the configured LiveDetector window
    should be removed.
    """

    detector = LiveDetector(
        window_seconds=60
    )

    start_time = datetime.now()

    old_event = create_event(
        start_time
    )

    recent_event = create_event(
        start_time + timedelta(
            seconds=70
        )
    )

    detector.add_event(old_event)

    assert len(detector.events) == 1

    detector.add_event(recent_event)

    assert len(detector.events) == 1

    assert detector.events[0].timestamp == recent_event.timestamp


def test_events_inside_window_are_kept():
    """
    Events that fall inside the configured window
    should remain available.
    """

    detector = LiveDetector(
        window_seconds=60
    )

    start_time = datetime.now()

    first_event = create_event(
        start_time
    )

    second_event = create_event(
        start_time + timedelta(
            seconds=30
        )
    )

    detector.add_event(first_event)
    detector.add_event(second_event)

    assert len(detector.events) == 2


def test_event_at_window_boundary_is_kept():
    """
    An event exactly at the cutoff should remain because
    the current implementation uses >= for the cutoff.
    """

    detector = LiveDetector(
        window_seconds=60
    )

    start_time = datetime.now()

    first_event = create_event(
        start_time
    )

    boundary_event = create_event(
        start_time + timedelta(
            seconds=60
        )
    )

    detector.add_event(first_event)
    detector.add_event(boundary_event)

    assert len(detector.events) == 2