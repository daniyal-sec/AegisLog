"""
AegisLog Real-Time Log Monitor

Watches a Linux authentication log and processes
new lines as they are written.
"""

import os
import time

from parser import parse_ssh_line
from live_detector import LiveDetector


def monitor_log(file_path, poll_interval=1):
    """
    Monitor a log file for new authentication events.

    Args:
        file_path: Path to the log file.
        poll_interval: Seconds between checks.
    """

    print("=" * 50)
    print("          AEGISLOG LIVE MONITOR")
    print("=" * 50)
    print(f"Monitoring : {file_path}")
    print("Status     : ACTIVE")
    print("Press Ctrl+C to stop.")
    print("=" * 50)
    print("")

    live_detector = LiveDetector()

    try:
        # --------------------------------------------------
        # Get the current end position of the log file.
        # This means we only process NEW entries.
        # --------------------------------------------------

        with open(file_path, "r", encoding="utf-8") as file:
            file.seek(0, os.SEEK_END)
            position = file.tell()

        # --------------------------------------------------
        # Monitor the file continuously.
        # --------------------------------------------------

        while True:

            with open(file_path, "r", encoding="utf-8") as file:

                file.seek(0, os.SEEK_END)
                file_size = file.tell()

                # Handle log truncation / rotation.
                if file_size < position:
                    position = 0

                file.seek(position)

                new_lines = file.readlines()

                position = file.tell()

            # --------------------------------------------------
            # Process every newly added line.
            # --------------------------------------------------

            for line in new_lines:

                event = parse_ssh_line(line)

                # Ignore lines that are not supported
                # authentication events.
                if not event:
                    continue

                # --------------------------------------------------
                # Display the live event.
                # --------------------------------------------------

                print(
                    f"[{event.timestamp.strftime('%b %d %H:%M:%S')}] "
                    f"{event.status:<8} "
                    f"{event.username:<15} "
                    f"{event.source_ip}"
                )

                # --------------------------------------------------
                # Run the event through the live detection engine.
                # --------------------------------------------------

                findings = live_detector.add_event(event)

                # --------------------------------------------------
                # Display detected threats immediately.
                # --------------------------------------------------

                for finding in findings:

                    print("")
                    print("!" * 50)
                    print("          AEGISLOG SECURITY ALERT")
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
                        f"IP Type     : {finding.ip_classification}"
                    )

                    print(
                        f"Target User : {finding.target_user}"
                    )

                    print(
                        f"Attempts    : {finding.attempts}"
                    )

                    print(
                        f"First Seen  : "
                        f"{finding.first_seen.strftime('%b %d %H:%M:%S')}"
                    )

                    print(
                        f"Last Seen   : "
                        f"{finding.last_seen.strftime('%b %d %H:%M:%S')}"
                    )

                    print("Recommendation")
                    print(
                        f"  {finding.recommendation}"
                    )

                    print("!" * 50)
                    print("")

            # --------------------------------------------------
            # Wait before checking the file again.
            # --------------------------------------------------

            time.sleep(poll_interval)

    except FileNotFoundError:

        print(
            f"Error: Log file not found: {file_path}"
        )

    except PermissionError:

        print(
            f"Error: Permission denied: {file_path}"
        )

    except KeyboardInterrupt:

        print("")
        print("AegisLog monitor stopped.")

    except OSError as error:

        print(
            f"Error: Unable to monitor log: {error}"
        )


if __name__ == "__main__":

    monitor_log(
        "sample_logs/live_test.log"
    )