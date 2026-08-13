"""
AegisLog Investigation Console

Provides an interactive CLI for investigating
stored authentication events and security findings.
"""

from datetime import datetime

from storage import SecurityStorage


class InvestigationConsole:
    """Interactive investigation interface for AegisLog."""

    def __init__(self, database_path="data/aegislog.db"):
        self.storage = SecurityStorage(database_path)

    # ==========================================================
    # MENU
    # ==========================================================

    def show_menu(self):
        """Display the investigation menu."""

        print()
        print("=" * 70)
        print("                 AEGISLOG INVESTIGATION")
        print("=" * 70)

        print("1. Recent Authentication Events")
        print("2. Failed Authentication Events")
        print("3. Search by IP")
        print("4. Search by Username")
        print("5. Search by Time Range")
        print("6. Security Findings")
        print("7. Findings by Severity")
        print("8. Findings by IP")
        print("9. Findings by Username")
        print("10. Investigate Finding")
        print("0. Exit")

        print("=" * 70)

    # ==========================================================
    # AUTHENTICATION EVENT DISPLAY
    # ==========================================================

    def show_auth_events(self, events):
        """Display authentication events in a readable format."""

        if not events:
            print()
            print("No authentication events found.")
            return

        print()
        print("=" * 80)
        print("                 AUTHENTICATION EVENTS")
        print("=" * 80)

        for event in events:

            print(f"ID        : {event['id']}")
            print(f"Time      : {event['timestamp']}")
            print(f"Status    : {event['status']}")
            print(f"Username  : {event['username']}")
            print(f"Source IP : {event['source_ip']}")
            print(f"Port      : {event['source_port']}")
            print(f"Service   : {event['service']}")
            print(f"Protocol  : {event['protocol']}")

            print("-" * 80)

        print(f"Total events: {len(events)}")

    # ==========================================================
    # SECURITY FINDING DISPLAY
    # ==========================================================

    def show_findings(self, findings):
        """Display security findings in a readable format."""

        if not findings:
            print()
            print("No security findings found.")
            return

        print()
        print("=" * 90)
        print("                    SECURITY FINDINGS")
        print("=" * 90)

        for finding in findings:

            print(f"ID               : {finding['id']}")
            print(f"Attack Type      : {finding['attack_type']}")
            print(f"Severity         : {finding['severity']}")
            print(f"Source IP        : {finding['source_ip']}")
            print(f"Target User      : {finding['target_user']}")
            print(f"Attempts         : {finding['attempts']}")
            print(f"Service          : {finding['service']}")
            print(
                f"IP Classification: "
                f"{finding['ip_classification']}"
            )
            print(f"Events           : {finding['event_count']}")
            print(f"Failed           : {finding['failed_attempts']}")
            print(
                f"Successful       : "
                f"{finding['successful_attempts']}"
            )
            print(
                f"Duration         : "
                f"{finding['duration_seconds']:.1f} seconds"
            )
            print(
                f"First Seen       : "
                f"{finding['first_seen']}"
            )
            print(
                f"Last Seen        : "
                f"{finding['last_seen']}"
            )
            print(
                f"Recommendation   : "
                f"{finding['recommendation']}"
            )

            print("-" * 90)

        print(f"Total findings: {len(findings)}")

    # ==========================================================
    # SEARCH BY IP
    # ==========================================================

    def search_by_ip(self):
        """Search authentication events by source IP."""

        source_ip = input(
            "Enter source IP: "
        ).strip()

        if not source_ip:
            print("Source IP cannot be empty.")
            return

        events = self.storage.get_auth_events_by_ip(
            source_ip
        )

        print()
        print(
            f"Search results for source: {source_ip}"
        )

        self.show_auth_events(events)

    # ==========================================================
    # SEARCH BY USERNAME
    # ==========================================================

    def search_by_username(self):
        """Search authentication events by username."""

        username = input(
            "Enter username: "
        ).strip()

        if not username:
            print("Username cannot be empty.")
            return

        events = (
            self.storage.get_auth_events_by_username(
                username
            )
        )

        print()
        print(
            f"Search results for username: {username}"
        )

        self.show_auth_events(events)

    # ==========================================================
    # SEARCH BY TIME RANGE
    # ==========================================================

    def search_by_time_range(self):
        """Search authentication events within a time range."""

        print()
        print("Time format:")
        print("YYYY-MM-DD HH:MM:SS")
        print()

        start_text = input(
            "Enter start time: "
        ).strip()

        end_text = input(
            "Enter end time: "
        ).strip()

        try:

            start_time = datetime.strptime(
                start_text,
                "%Y-%m-%d %H:%M:%S",
            )

            end_time = datetime.strptime(
                end_text,
                "%Y-%m-%d %H:%M:%S",
            )

        except ValueError:

            print()
            print("Invalid time format.")
            print("Use: YYYY-MM-DD HH:MM:SS")

            return

        if start_time > end_time:

            print()
            print(
                "Start time cannot be later "
                "than end time."
            )

            return

        events = (
            self.storage.get_auth_events_between(
                start_time,
                end_time,
            )
        )

        print()
        print("Search results:")
        print(f"{start_time} -> {end_time}")

        self.show_auth_events(events)

    # ==========================================================
    # FINDINGS
    # ==========================================================

    def show_all_findings(self):
        """Display all stored security findings."""

        findings = self.storage.get_findings()

        self.show_findings(findings)

    # ==========================================================
    # FINDINGS BY SEVERITY
    # ==========================================================

    def search_findings_by_severity(self):
        """Search security findings by severity."""

        severity = input(
            "Enter severity "
            "(LOW/MEDIUM/HIGH/CRITICAL): "
        ).strip().upper()

        if not severity:
            print("Severity cannot be empty.")
            return

        findings = (
            self.storage.get_findings_by_severity(
                severity
            )
        )

        print()
        print(
            f"Search results for severity: "
            f"{severity}"
        )

        self.show_findings(findings)

    # ==========================================================
    # FINDINGS BY IP
    # ==========================================================

    def search_findings_by_ip(self):
        """Search security findings by source IP."""

        source_ip = input(
            "Enter source IP: "
        ).strip()

        if not source_ip:
            print("Source IP cannot be empty.")
            return

        findings = (
            self.storage.get_findings_by_ip(
                source_ip
            )
        )

        print()
        print(
            f"Search results for source IP: "
            f"{source_ip}"
        )

        self.show_findings(findings)

    # ==========================================================
    # FINDINGS BY USERNAME
    # ==========================================================

    def search_findings_by_username(self):
        """Search security findings by target username."""

        username = input(
            "Enter target username: "
        ).strip()

        if not username:
            print("Username cannot be empty.")
            return

        findings = (
            self.storage.get_findings_by_username(
                username
            )
        )

        print()
        print(
            f"Search results for target username: "
            f"{username}"
        )

        self.show_findings(findings)

    # ==========================================================
    # INCIDENT INVESTIGATION
    # ==========================================================

    def investigate_finding(self):
        """Investigate a security finding and its related events."""

        finding_text = input(
            "Enter finding ID: "
        ).strip()

        if not finding_text:
            print("Finding ID cannot be empty.")
            return

        try:
            finding_id = int(finding_text)

        except ValueError:
            print("Finding ID must be a number.")
            return

        finding = self.storage.get_finding_by_id(
            finding_id
        )

        if finding is None:

            print()
            print(
                f"No finding found with ID "
                f"{finding_id}."
            )

            return

        print()
        print("=" * 70)
        print("                 INCIDENT INVESTIGATION")
        print("=" * 70)

        print(
            f"Finding ID       : "
            f"{finding['id']}"
        )

        print(
            f"Attack Type      : "
            f"{finding['attack_type']}"
        )

        print(
            f"Severity         : "
            f"{finding['severity']}"
        )

        print(
            f"Source IP        : "
            f"{finding['source_ip']}"
        )

        print(
            f"Target User      : "
            f"{finding['target_user']}"
        )

        print(
            f"Attempts         : "
            f"{finding['attempts']}"
        )

        print(
            f"First Seen       : "
            f"{finding['first_seen']}"
        )

        print(
            f"Last Seen        : "
            f"{finding['last_seen']}"
        )

        print("=" * 70)

        try:

            first_seen = datetime.fromisoformat(
                finding["first_seen"]
            )

            last_seen = datetime.fromisoformat(
                finding["last_seen"]
            )

        except ValueError:

            print()
            print(
                "Unable to parse finding timestamps."
            )

            return

        events = (
            self.storage.get_auth_events_between(
                first_seen,
                last_seen,
            )
        )

        # Only keep events belonging to this finding.
        related_events = [
            event
            for event in events
            if event["source_ip"] == finding["source_ip"]
            and event["username"] == finding["target_user"]
        ]

        print()
        print("=" * 80)
        print("                    EVENT TIMELINE")
        print("=" * 80)

        if not related_events:

            print(
                "No related authentication events found."
            )

        else:

            for event in related_events:

                print(
                    f"{event['timestamp']}   "
                    f"{event['status']:<9} "
                    f"{event['username']}   "
                    f"{event['source_ip']}"
                )

        print("=" * 80)

        print()
        print("=" * 70)
        print("                 INVESTIGATION SUMMARY")
        print("=" * 70)

        print(
            f"Events      : "
            f"{finding['event_count']}"
        )

        print(
            f"Failed      : "
            f"{finding['failed_attempts']}"
        )

        print(
            f"Successful  : "
            f"{finding['successful_attempted']}"
            if "successful_attempted" in finding
            else
            f"Successful  : "
            f"{finding['successful_attempts']}"
        )

        print(
            f"Duration    : "
            f"{finding['duration_seconds']:.1f} seconds"
        )

        print()
        print("Recommendation:")
        print(
            finding["recommendation"]
        )

        print("=" * 70)

    # ==========================================================
    # MAIN LOOP
    # ==========================================================

    def run(self):
        """Start the interactive investigation console."""

        while True:

            self.show_menu()

            choice = input(
                "Select an option: "
            ).strip()

            if choice == "0":

                print()
                print(
                    "Exiting AegisLog Investigation."
                )

                break

            elif choice == "1":

                events = (
                    self.storage.get_auth_events()
                )

                self.show_auth_events(events)

            elif choice == "2":

                events = (
                    self.storage.get_failed_auth_events()
                )

                self.show_auth_events(events)

            elif choice == "3":

                self.search_by_ip()

            elif choice == "4":

                self.search_by_username()

            elif choice == "5":

                self.search_by_time_range()

            elif choice == "6":

                self.show_all_findings()

            elif choice == "7":

                self.search_findings_by_severity()

            elif choice == "8":

                self.search_findings_by_ip()

            elif choice == "9":

                self.search_findings_by_username()

            elif choice == "10":

                self.investigate_finding()

            else:

                print()
                print(
                    "Invalid option. "
                    "Please select 0-10."
                )


if __name__ == "__main__":
    console = InvestigationConsole()
    console.run()