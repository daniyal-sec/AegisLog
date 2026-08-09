"""
AegisLog Windows Detection Test

Tests Windows-style failed authentication events
against the existing LiveDetector without generating
real failed logins on the Windows account.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add AegisLog/src to Python's import path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import AuthEvent
from live_detector import LiveDetector


def create_failed_event(timestamp, attempt):
    """
    Create a simulated Windows failed authentication event.
    """

    return AuthEvent(
        timestamp=timestamp,
        hostname="Windows-Test",
        service="Windows Authentication",
        pid=0,
        status="FAILED",
        username="TEST_USER",
        source_ip="192.168.1.50",
        source_port=0,
        protocol="Windows Security",
        invalid_user=False,
        raw_log=(
            f"Test Windows 4625 event "
            f"attempt={attempt}"
        ),
    )


def main():
    """
    Generate five failed Windows authentication events
    and send them through the real LiveDetector.
    """

    detector = LiveDetector()

    start_time = datetime.now()

    print("=" * 60)
    print("       AEGISLOG WINDOWS DETECTION TEST")
    print("=" * 60)
    print("")

    for attempt in range(1, 6):

        timestamp = start_time + timedelta(
            seconds=attempt * 4
        )

        event = create_failed_event(
            timestamp,
            attempt
        )

        findings = detector.add_event(event)

        print(
            f"[{timestamp.strftime('%H:%M:%S')}] "
            f"Windows 4625 FAILED "
            f"TEST_USER "
            f"192.168.1.50 "
            f"Attempt {attempt}"
        )

        for finding in findings:

            print("")
            print("!" * 50)
            print("       AEGISLOG SECURITY ALERT")
            print("!" * 50)

            print(
                f"Attack Type : {finding.attack_type}"
            )

            print(
                f"Severity    : {finding.severity}"
            )

            print(
                f"Source IP   : {finding.source_ip}"
            )

            print(
                f"Target User : {finding.target_user}"
            )

            print(
                f"Attempts    : {finding.attempts}"
            )

            print("Recommendation")
            print(
                finding.recommendation
            )

            print("!" * 50)

    print("")
    print("=" * 60)
    print("Windows detection test complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()