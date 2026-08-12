"""
AegisLog Windows Parser Tests

Tests the Windows Security Event Log parser using
synthetic event objects. No real Windows events are
required.
"""

import sys
from pathlib import Path
from datetime import datetime

# Add AegisLog/src to Python's import path.

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from windows_parser import (
    parse_windows_event,
    classify_ip,
)


class FakeWindowsEvent:
    """Minimal fake Windows event used for parser testing."""

    def __init__(
        self,
        event_id,
        fields,
        timestamp=None,
    ):
        self.EventID = event_id
        self.StringInserts = fields
        self.TimeGenerated = (
            timestamp
            if timestamp is not None
            else datetime.now()
        )


def create_event(
    event_id,
    username="TEST_USER",
    logon_type="3",
    source_ip="192.168.1.50",
    source_port="445",
):
    """
    Create a synthetic Windows 4624/4625 event.

    Windows Security Event fields used by the parser:

        [5]  Target Username
        [10] Logon Type
        [19] Source IP
        [20] Source Port
    """

    # Windows Security 4624/4625 events contain
    # at least 21 StringInserts fields for the
    # structure used by AegisLog.

    fields = ["-"] * 21

    fields[5] = username
    fields[10] = logon_type
    fields[19] = source_ip
    fields[20] = source_port

    return FakeWindowsEvent(
        event_id=event_id,
        fields=fields,
    )


def test_successful_logon_4624():
    """Verify Windows Event ID 4624 becomes a SUCCESS event."""

    event = create_event(
        event_id=4624,
        username="TEST_USER",
        logon_type="3",
        source_ip="192.168.1.50",
        source_port="445",
    )

    result = parse_windows_event(event)

    assert result is not None
    assert result.status == "SUCCESS"
    assert result.username == "TEST_USER"
    assert result.source_ip == "192.168.1.50"
    assert result.source_port == 445
    assert result.service == "Windows Authentication"
    assert result.protocol == "Windows Security"


def test_failed_logon_4625():
    """Verify Windows Event ID 4625 becomes a FAILED event."""

    event = create_event(
        event_id=4625,
        username="TEST_USER",
        logon_type="3",
        source_ip="192.168.1.50",
        source_port="445",
    )

    result = parse_windows_event(event)

    assert result is not None
    assert result.status == "FAILED"
    assert result.username == "TEST_USER"
    assert result.source_ip == "192.168.1.50"
    assert result.source_port == 445


def test_loopback_address_is_normalized_to_local():
    """
    Verify that the parser normalizes
    127.0.0.1 to 'local'.
    """

    event = create_event(
        event_id=4624,
        username="TEST_USER",
        logon_type="11",
        source_ip="127.0.0.1",
        source_port="0",
    )

    result = parse_windows_event(event)

    assert result is not None
    assert result.source_ip == "local"


def test_missing_source_ip_is_normalized_to_local():
    """Verify '-' source IP is treated as local."""

    event = create_event(
        event_id=4624,
        username="TEST_USER",
        logon_type="2",
        source_ip="-",
        source_port="-",
    )

    result = parse_windows_event(event)

    assert result is not None
    assert result.source_ip == "local"
    assert result.source_port == 0


def test_service_logon_is_ignored():
    """Verify Logon Type 5 service events are ignored."""

    event = create_event(
        event_id=4624,
        username="SYSTEM",
        logon_type="5",
        source_ip="-",
        source_port="-",
    )

    result = parse_windows_event(event)

    assert result is None


def test_event_without_username_is_ignored():
    """Verify authentication events without a username are ignored."""

    event = create_event(
        event_id=4625,
        username="-",
        logon_type="3",
        source_ip="192.168.1.50",
        source_port="445",
    )

    result = parse_windows_event(event)

    assert result is None


def test_unsupported_event_is_ignored():
    """Verify unrelated Windows event IDs are ignored."""

    event = create_event(
        event_id=4688,
        username="TEST_USER",
        logon_type="3",
        source_ip="192.168.1.50",
        source_port="445",
    )

    result = parse_windows_event(event)

    assert result is None


def test_ip_classification():
    """Verify the IP classification helper."""

    assert classify_ip(
        "127.0.0.1",
        "11",
    ) == "loopback"

    assert classify_ip(
        "192.168.1.50",
        "3",
    ) == "private"

    assert classify_ip(
        "",
        "2",
    ) == "local"

    assert classify_ip(
        "-",
        "7",
    ) == "local"

    assert classify_ip(
        "not-an-ip",
        "3",
    ) == "unknown"

def test_failed_logon_falls_back_to_subject_username():
    """
    Verify that a Windows 4625 event with a missing
    TargetUserName falls back to SubjectUserName.
    """

    fields = ["-"] * 21

    fields[1] = "danyyy"
    fields[5] = "-"
    fields[10] = "2"
    fields[19] = "::1"
    fields[20] = "0"

    event = FakeWindowsEvent(
        event_id=4625,
        fields=fields,
    )

    result = parse_windows_event(event)

    assert result is not None
    assert result.status == "FAILED"
    assert result.username == "danyyy"
    assert result.source_ip == "local"
    assert result.source_port == 0
