"""
AegisLog Parser Timestamp Year Tests

Verifies that parse_ssh_line() correctly assigns the current year to
parsed timestamps (instead of the 1900 default from strptime) and
handles December/January year-boundary cases.
"""

import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from parser import parse_ssh_line


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_line(month_day_time="Aug 14 12:00:00", pid=1234, message="Accepted password for testuser from 192.168.1.10 port 54321 ssh2"):
    return f"{month_day_time} testhost sshd[{pid}]: {message}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_ssh_line_year_is_not_1900():
    """Parsed timestamp must use the current year, not 1900."""
    line = _make_line("Aug 14 12:00:00")
    event = parse_ssh_line(line)
    assert event is not None
    assert event.timestamp.year != 1900
    assert event.timestamp.year == datetime.now().year


def test_parse_ssh_line_year_is_current_year():
    """Year must equal datetime.now().year in the normal mid-year case."""
    line = _make_line("Jun 01 08:00:00")
    event = parse_ssh_line(line)
    assert event is not None
    now_year = datetime.now().year
    assert event.timestamp.year == now_year


def test_parse_ssh_line_december_in_january_boundary():
    """
    When we are in January and the log line is from December, the
    parser must assign the previous year.
    """
    # Mock datetime.now() so that "now" is January 2026
    mock_now = datetime(2026, 1, 5, 10, 0, 0)
    with patch("parser.datetime") as mock_dt:
        mock_dt.now.return_value = mock_now
        mock_dt.strptime.side_effect = datetime.strptime  # keep real strptime

        line = _make_line("Dec 31 23:59:59")
        event = parse_ssh_line(line)

    assert event is not None
    # December log arriving in January ? last year
    assert event.timestamp.year == 2025
    assert event.timestamp.month == 12


def test_parse_ssh_line_january_in_december_boundary():
    """
    When we are in December and the log line is from January, the
    parser must assign the next year.
    """
    mock_now = datetime(2025, 12, 31, 23, 0, 0)
    with patch("parser.datetime") as mock_dt:
        mock_dt.now.return_value = mock_now
        mock_dt.strptime.side_effect = datetime.strptime

        line = _make_line("Jan 01 00:01:00")
        event = parse_ssh_line(line)

    assert event is not None
    # January log arriving in December ? next year
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 1


def test_parse_ssh_line_failed_event_year_correct():
    """Year fix applies equally to FAILED authentication events."""
    line = _make_line(
        "Aug 14 14:30:00",
        message="Failed password for root from 10.0.0.1 port 22345 ssh2",
    )
    event = parse_ssh_line(line)
    assert event is not None
    assert event.timestamp.year == datetime.now().year
    assert event.status == "FAILED"


def test_parse_ssh_line_invalid_user_year_correct():
    """Year fix applies to invalid-user events."""
    line = _make_line(
        "Aug 14 14:30:00",
        message="Failed password for invalid user nobody from 10.0.0.2 port 22346 ssh2",
    )
    event = parse_ssh_line(line)
    assert event is not None
    assert event.timestamp.year == datetime.now().year
    assert event.invalid_user is True
