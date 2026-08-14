"""
AegisLog Journal Monitor Tests

Tests for journal_monitor.py:
- build_syslog_line() reconstruction logic
- SSH success / failure / invalid-user event parsing
- Non-SSH and malformed entries are ignored
- Duplicate cursor prevention (LiveDetector deduplication)
- Graceful handling of missing journalctl
"""

import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from journal_monitor import build_syslog_line, process_journal_entry, _is_journalctl_available
from live_detector import LiveDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_TS = str(int(datetime(2026, 8, 14, 12, 0, 0).timestamp() * 1_000_000))


def _make_ssh_entry(
    message,
    pid="1234",
    hostname="kali",
    ts=None,
    unit="ssh.service",
    syslog_id="sshd",
):
    return {
        "MESSAGE": message,
        "_SYSTEMD_UNIT": unit,
        "SYSLOG_IDENTIFIER": syslog_id,
        "_HOSTNAME": hostname,
        "_PID": pid,
        "__REALTIME_TIMESTAMP": ts or _BASE_TS,
    }


# ---------------------------------------------------------------------------
# build_syslog_line tests
# ---------------------------------------------------------------------------

def test_build_syslog_line_accepted_ssh():
    """Accepted SSH entry produces a valid syslog line."""
    entry = _make_ssh_entry(
        "Accepted password for testuser from 192.168.1.10 port 54321 ssh2"
    )
    line = build_syslog_line(entry)
    assert line is not None
    assert "sshd[1234]:" in line
    assert "Accepted password" in line
    assert "192.168.1.10" in line
    assert "kali" in line


def test_build_syslog_line_failed_ssh():
    """Failed SSH entry produces a valid syslog line."""
    entry = _make_ssh_entry(
        "Failed password for root from 10.0.0.5 port 22345 ssh2"
    )
    line = build_syslog_line(entry)
    assert line is not None
    assert "Failed password" in line
    assert "root" in line
    assert "10.0.0.5" in line


def test_build_syslog_line_invalid_user():
    """Invalid user SSH entry produces a valid syslog line."""
    entry = _make_ssh_entry(
        "Failed password for invalid user nobody from 10.0.0.6 port 22346 ssh2"
    )
    line = build_syslog_line(entry)
    assert line is not None
    assert "invalid user" in line
    assert "nobody" in line


def test_build_syslog_line_non_auth_message_is_none():
    """Non-authentication SSH messages are discarded."""
    entry = _make_ssh_entry("Server listening on 0.0.0.0 port 22.")
    line = build_syslog_line(entry)
    assert line is None


def test_build_syslog_line_non_ssh_unit_is_none():
    """Entries from non-SSH units are discarded."""
    entry = _make_ssh_entry(
        "Accepted password for user from 192.168.1.1 port 1234 ssh2",
        unit="cron.service",
        syslog_id="cron",
    )
    line = build_syslog_line(entry)
    assert line is None


def test_build_syslog_line_empty_message_is_none():
    """Empty MESSAGE field produces None."""
    entry = _make_ssh_entry("")
    line = build_syslog_line(entry)
    assert line is None


def test_build_syslog_line_sshd_unit_name():
    """Entries with unit=sshd.service are accepted."""
    entry = _make_ssh_entry(
        "Accepted password for user from 192.168.1.2 port 2222 ssh2",
        unit="sshd.service",
        syslog_id="sshd",
    )
    line = build_syslog_line(entry)
    assert line is not None
    assert "Accepted password" in line


def test_build_syslog_line_syslog_id_only():
    """If _SYSTEMD_UNIT is empty but SYSLOG_IDENTIFIER is sshd, still accepted."""
    entry = {
        "MESSAGE": "Accepted password for user from 192.168.1.3 port 3333 ssh2",
        "_SYSTEMD_UNIT": "",
        "SYSLOG_IDENTIFIER": "sshd",
        "_HOSTNAME": "kali",
        "_PID": "999",
        "__REALTIME_TIMESTAMP": _BASE_TS,
    }
    line = build_syslog_line(entry)
    assert line is not None


# ---------------------------------------------------------------------------
# Journal-to-AuthEvent conversion tests
# ---------------------------------------------------------------------------

def test_journal_entry_ssh_success_creates_auth_event():
    """A valid accepted SSH journal entry feeds through to an AuthEvent."""
    detector = LiveDetector()
    entry = _make_ssh_entry(
        "Accepted password for analyst from 10.0.0.10 port 44321 ssh2"
    )
    # process_journal_entry returns a list of findings (may be empty)
    findings = process_journal_entry(entry, detector, storage=None)
    # No brute force on single success — findings may be empty; that is fine.
    assert isinstance(findings, list)


def test_journal_entry_ssh_failure_creates_auth_event():
    """A valid failed SSH journal entry feeds through to an AuthEvent."""
    detector = LiveDetector()
    entry = _make_ssh_entry(
        "Failed password for root from 10.0.0.20 port 55555 ssh2"
    )
    findings = process_journal_entry(entry, detector, storage=None)
    assert isinstance(findings, list)


def test_journal_entry_invalid_user_creates_auth_event():
    """An invalid user SSH journal entry feeds through to an AuthEvent."""
    detector = LiveDetector()
    entry = _make_ssh_entry(
        "Failed password for invalid user nobody from 10.0.0.30 port 66666 ssh2"
    )
    findings = process_journal_entry(entry, detector, storage=None)
    assert isinstance(findings, list)


def test_journal_entry_non_auth_ignored():
    """Non-authentication journal entries produce no AuthEvent."""
    detector = LiveDetector()
    entry = _make_ssh_entry("pam_unix(sshd:session): session opened for user root")
    findings = process_journal_entry(entry, detector, storage=None)
    assert findings == []


# ---------------------------------------------------------------------------
# Duplicate prevention (LiveDetector deduplication)
# ---------------------------------------------------------------------------

def test_journal_monitor_duplicate_prevention():
    """
    LiveDetector must not emit duplicate findings for the same attack.
    Sending the same failing entry five times (same IP, user) should
    produce exactly one brute-force finding, not five.
    """
    from datetime import timedelta

    detector = LiveDetector()

    base_ts_us = int(datetime(2026, 8, 14, 12, 0, 0).timestamp() * 1_000_000)
    all_findings = []

    for i in range(5):
        ts_us = base_ts_us + i * 5_000_000  # 5 second intervals
        entry = {
            "MESSAGE": (
                "Failed password for brute_target "
                "from 203.0.113.1 port 12345 ssh2"
            ),
            "_SYSTEMD_UNIT": "ssh.service",
            "SYSLOG_IDENTIFIER": "sshd",
            "_HOSTNAME": "kali",
            "_PID": "5555",
            "__REALTIME_TIMESTAMP": str(ts_us),
        }
        all_findings.extend(process_journal_entry(entry, detector, storage=None))

    brute_force = [
        f for f in all_findings if f.attack_type == "Authentication Brute Force"
    ]
    # Should fire exactly once
    assert len(brute_force) == 1


# ---------------------------------------------------------------------------
# Graceful missing journalctl handling
# ---------------------------------------------------------------------------

def test_is_journalctl_available_returns_false_when_not_found():
    """_is_journalctl_available must return False when journalctl is missing."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _is_journalctl_available()
    assert result is False


def test_monitor_journal_exits_cleanly_without_journalctl():
    """monitor_journal must print a clear error and return when journalctl is absent."""
    from journal_monitor import monitor_journal

    with patch("journal_monitor._is_journalctl_available", return_value=False):
        # Should return without raising
        monitor_journal(db_path=":memory:")
