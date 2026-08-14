"""
AegisLog Linux Journal Monitor

Monitors the systemd journal for SSH authentication events in real time.
This is the recommended monitor for Kali Linux and other systemd-based
distributions where SSH events are stored in the journal rather than a
plain-text log file (e.g. /var/log/auth.log).

Architecture
------------
systemd journal (SSH entries)
        |
  journalctl subprocess
        |
   raw MESSAGE field
        |
  reconstruct syslog line
        |
    parse_ssh_line()        <- reuses existing parser unchanged
        |
       AuthEvent
        |
     LiveDetector           <- existing detection engine
        |
    ThreatFinding
        |
   SecurityStorage          <- existing SQLite persistence

Usage
-----
    python src/journal_monitor.py

Requirements
------------
- Linux with systemd
- journalctl in PATH (standard on all systemd distros)
- Run as a user with access to the systemd journal

No additional pip packages are required.
"""

import json
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure src/ is importable when run directly
# ---------------------------------------------------------------------------
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from live_detector import LiveDetector
from parser import parse_ssh_line
from storage import SecurityStorage


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SYSLOG_MONTH_ABBR = {
    1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr",
    5: "May", 6: "Jun", 7: "Jul", 8: "Aug",
    9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec",
}

_SSH_UNIT_NAMES = ("ssh.service", "sshd.service", "ssh", "sshd")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_journalctl_available():
    """Return True if journalctl is present and executable."""
    try:
        result = subprocess.run(
            ["journalctl", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def build_syslog_line(entry):
    """
    Reconstruct a syslog-format line from a journald JSON entry so it
    can be passed through the existing parse_ssh_line() parser.

    Returns None if the entry does not look like an SSH authentication
    message.

    Parameters
    ----------
    entry : dict
        Parsed JSON object from journalctl --output=json.

    Returns
    -------
    str or None
        A line in the form:
            Aug 06 14:39:13 hostname sshd[pid]: message
    """
    message = entry.get("MESSAGE", "")
    if not message:
        return None

    # Only process SSH/sshd entries
    unit = entry.get("_SYSTEMD_UNIT", "") or entry.get("UNIT", "") or ""
    syslog_id = entry.get("SYSLOG_IDENTIFIER", "")

    is_ssh = (
        any(unit.lower() == u for u in _SSH_UNIT_NAMES)
        or syslog_id.lower() in ("sshd", "ssh")
    )
    if not is_ssh:
        return None

    # Only authentication events are relevant
    if not re.search(
        r"(Accepted|Failed)\s+password",
        message,
        re.IGNORECASE,
    ):
        return None

    # Parse the journal realtime timestamp (microseconds since epoch, UTC)
    ts_str = entry.get("__REALTIME_TIMESTAMP", "")
    try:
        ts = datetime.utcfromtimestamp(int(ts_str) / 1_000_000)
    except (ValueError, TypeError):
        ts = datetime.utcnow()

    month_abbr = _SYSLOG_MONTH_ABBR[ts.month]
    day_str = f"{ts.day:2d}"
    time_str = ts.strftime("%H:%M:%S")

    # Hostname
    hostname = (
        entry.get("_HOSTNAME")
        or socket.gethostname()
    )

    # PID
    pid = entry.get("_PID") or entry.get("SYSLOG_PID") or "0"

    return (
        f"{month_abbr} {day_str} {time_str} "
        f"{hostname} sshd[{pid}]: {message}"
    )


def _print_finding(finding):
    """Print a security finding to stdout."""
    print("")
    print("!" * 50)
    print("          AEGISLOG SECURITY ALERT")
    print("!" * 50)
    print(f"Attack Type : {finding.attack_type}")
    print(f"Severity    : {finding.severity}")
    print(f"Source IP   : {finding.source_ip}")
    if finding.ip_classification:
        print(f"IP Type     : {finding.ip_classification}")
    print(f"Target User : {finding.target_user}")
    print(f"Attempts    : {finding.attempts}")

    first_seen = finding.first_seen
    last_seen = finding.last_seen
    if hasattr(first_seen, "strftime"):
        first_seen = first_seen.strftime("%b %d %H:%M:%S")
    if hasattr(last_seen, "strftime"):
        last_seen = last_seen.strftime("%b %d %H:%M:%S")

    print(f"First Seen  : {first_seen}")
    print(f"Last Seen   : {last_seen}")
    print("Recommendation")
    print(f"  {finding.recommendation}")
    print("!" * 50)
    print("")


# ---------------------------------------------------------------------------
# Public API -- used by tests
# ---------------------------------------------------------------------------

def process_journal_entry(entry, detector, storage):
    """
    Process one journald JSON entry through the detection pipeline.

    Parameters
    ----------
    entry : dict
        Parsed JSON entry from journalctl.
    detector : LiveDetector
        Shared LiveDetector instance.
    storage : SecurityStorage or None
        SecurityStorage instance. May be None during tests.

    Returns
    -------
    list[ThreatFinding]
        Any newly detected findings (may be empty).
    """
    line = build_syslog_line(entry)
    if not line:
        return []

    event = parse_ssh_line(line)
    if not event:
        return []

    print(
        f"[{event.timestamp.strftime('%b %d %H:%M:%S')}] "
        f"{event.status:<8} "
        f"{event.username:<15} "
        f"{event.source_ip}"
    )

    if storage is not None:
        storage.save_auth_event(event)

    findings = detector.add_event(event)

    for finding in findings:
        if storage is not None:
            storage.save_finding(finding)
        _print_finding(finding)

    return findings


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

def monitor_journal(db_path="data/aegislog.db", poll_interval=1.0):
    """
    Monitor the systemd journal for SSH authentication events in real time.

    Parameters
    ----------
    db_path : str
        Path to the AegisLog SQLite database.
    poll_interval : float
        Seconds to wait between journal reconnection attempts if the
        process exits unexpectedly.
    """
    if not _is_journalctl_available():
        print("ERROR: journalctl is not available on this system.")
        print("       This monitor requires Linux with systemd.")
        print("       File-based fallback: python src/monitor.py")
        return

    print("=" * 50)
    print("     AEGISLOG LINUX JOURNAL MONITOR")
    print("=" * 50)
    print("Source     : systemd journal (SSH)")
    print("Status     : ACTIVE")
    print("Press Ctrl+C to stop.")
    print("=" * 50)
    print("")

    detector = LiveDetector()

    try:
        storage = SecurityStorage(db_path)
    except Exception as exc:
        print(f"WARNING: Could not open database: {exc}")
        print("         Events will be processed but not persisted.")
        storage = None

    # journalctl command:
    #   --follow      stream new entries as they arrive
    #   --output=json one JSON object per line
    #   --unit=ssh    filter to SSH service (Debian/Kali: ssh.service)
    #   --since=now   start from current cursor, skip historical entries
    #
    # We try ssh.service first; many distros name the unit sshd.service.
    # journalctl will return zero results (not an error) when the unit
    # does not exist under that name, so we fall back gracefully.
    for unit_name in ("ssh", "sshd"):
        cmd = [
            "journalctl",
            "--follow",
            "--output=json",
            f"--unit={unit_name}",
            "--since=now",
        ]

        print(f"Waiting for new SSH events (unit={unit_name}.service)...")
        print("")

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            got_event = False
            for raw_line in proc.stdout:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue

                try:
                    entry = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue

                process_journal_entry(entry, detector, storage)
                got_event = True

            # If the process exited cleanly without any events, try next
            # unit name.
            if not got_event:
                continue

            # If we processed events but the stream ended, restart.
            time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("")
            print("AegisLog journal monitor stopped.")
            return

        except Exception as error:
            print(f"ERROR: Journal monitor failed: {error}")
            return

        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass


if __name__ == "__main__":
    import argparse as _argparse

    _parser = _argparse.ArgumentParser(
        description=(
            "AegisLog Linux Journal Monitor -- "
            "monitors systemd journal for SSH events"
        )
    )
    _parser.add_argument(
        "--db",
        default="data/aegislog.db",
        help="Path to AegisLog SQLite database (default: data/aegislog.db)",
    )
    _args = _parser.parse_args()

    monitor_journal(db_path=_args.db)
