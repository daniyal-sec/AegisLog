"""
AegisLog Detection Engine Tests

Tests the shared LiveDetector against synthetic authentication
events without generating real authentication attempts.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add AegisLog/src to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent
from live_detector import LiveDetector


def create_event(
    timestamp,
    username,
    source_ip="192.168.1.50",
    status="FAILED",
    invalid_user=False,
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
        invalid_user=invalid_user,
        raw_log=(
            f"Test authentication event | "
            f"User={username} | "
            f"Source={source_ip} | "
            f"Status={status}"
        ),
    )


def test_windows_brute_force_detection():
    """Five failed attempts against one account trigger brute force."""

    detector = LiveDetector()

    start_time = datetime.now()

    findings = []

    for attempt in range(5):

        timestamp = start_time + timedelta(
            seconds=attempt * 5
        )

        event = create_event(
            timestamp=timestamp,
            username="TEST_USER",
            source_ip="192.168.1.50",
            status="FAILED",
        )

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

    assert finding.severity == "HIGH"
    assert finding.source_ip == "192.168.1.50"
    assert finding.target_user == "TEST_USER"
    assert finding.attempts == 5


def test_brute_force_requires_five_attempts():
    """Four failed attempts must not trigger brute force."""

    detector = LiveDetector()

    start_time = datetime.now()

    findings = []

    for attempt in range(4):

        event = create_event(
            timestamp=start_time + timedelta(
                seconds=attempt * 5
            ),
            username="TEST_USER",
            source_ip="192.168.1.50",
            status="FAILED",
        )

        findings.extend(
            detector.add_event(event)
        )

    brute_force = [
        finding
        for finding in findings
        if finding.attack_type == "Authentication Brute Force"
    ]

    assert len(brute_force) == 0


def test_username_enumeration_detection():
    """Three different invalid usernames from one IP trigger enumeration."""

    detector = LiveDetector()

    start_time = datetime.now()

    usernames = [
        "admin_test",
        "backup_test",
        "security_test",
    ]

    findings = []

    for index, username in enumerate(usernames):

        event = create_event(
            timestamp=start_time + timedelta(
                seconds=index * 5
            ),
            username=username,
            source_ip="192.168.1.60",
            status="FAILED",
            invalid_user=True,
        )

        findings.extend(
            detector.add_event(event)
        )

    enumeration = [
        finding
        for finding in findings
        if finding.attack_type == "Username Enumeration"
    ]

    assert len(enumeration) == 1

    finding = enumeration[0]

    assert finding.severity == "MEDIUM"
    assert finding.source_ip == "192.168.1.60"
    assert finding.attempts == 3


def test_password_spraying_detection():
    """Four different usernames from one IP trigger password spraying."""

    detector = LiveDetector()

    start_time = datetime.now()

    usernames = [
        "user_one",
        "user_two",
        "user_three",
        "user_four",
    ]

    findings = []

    for index, username in enumerate(usernames):

        event = create_event(
            timestamp=start_time + timedelta(
                seconds=index * 5
            ),
            username=username,
            source_ip="192.168.1.70",
            status="FAILED",
        )

        findings.extend(
            detector.add_event(event)
        )

    spraying = [
        finding
        for finding in findings
        if finding.attack_type == "Password Spraying"
    ]

    assert len(spraying) == 1

    finding = spraying[0]

    assert finding.severity == "HIGH"
    assert finding.source_ip == "192.168.1.70"
    assert finding.attempts == 4


def test_successful_login_after_failures():
    """
    Verify successful authentication after three failures
    is detected as a critical finding.

    The current detector uses status='ACCEPTED' for this rule.
    """

    detector = LiveDetector()

    start_time = datetime.now()

    findings = []

    # Three failed attempts.
    for attempt in range(3):

        event = create_event(
            timestamp=start_time + timedelta(
                seconds=attempt * 5
            ),
            username="TEST_USER",
            source_ip="192.168.1.80",
            status="FAILED",
        )

        findings.extend(
            detector.add_event(event)
        )

    # Successful login.
    success_event = create_event(
        timestamp=start_time + timedelta(
            seconds=20
        ),
        username="TEST_USER",
        source_ip="192.168.1.80",
        status="ACCEPTED",
    )

    findings.extend(
        detector.add_event(success_event)
    )

    successful_login = [
        finding
        for finding in findings
        if finding.attack_type
        == "Successful login after multiple failures"
    ]

    assert len(successful_login) == 1

    finding = successful_login[0]

    assert finding.severity == "CRITICAL"
    assert finding.source_ip == "192.168.1.80"
    assert finding.target_user == "TEST_USER"
    assert finding.attempts == 3


def test_root_login_detection():
    """Verify an accepted root login generates a security finding."""

    detector = LiveDetector()

    event = create_event(
        timestamp=datetime.now(),
        username="root",
        source_ip="192.168.1.90",
        status="ACCEPTED",
    )

    findings = detector.add_event(event)

    root_findings = [
        finding
        for finding in findings
        if finding.attack_type == "Root Login"
    ]

    assert len(root_findings) == 1

    finding = root_findings[0]

    assert finding.severity == "HIGH"
    assert finding.source_ip == "192.168.1.90"
    assert finding.target_user == "root"
    assert finding.attempts == 1