"""
AegisLog Live Detection Engine

Maintains a rolling buffer of recent authentication
events, correlates related activity, and prevents
duplicate alerts for the same attack activity.
"""

from datetime import timedelta

from detector import (
    detect_bruteforce,
    detect_username_enumeration,
    detect_success_after_failures,
    detect_password_spraying,
    detect_root_login,
)

from correlator import EventCorrelator
from utils import enrich_findings


class LiveDetector:

    def __init__(self, window_seconds=300):
        """
        Args:
            window_seconds: How long events remain in
                            the rolling detection buffer.
        """

        self.window = timedelta(
            seconds=window_seconds
        )

        self.events = []

        # Correlation engine uses the same window
        # as the live detector.
        self.correlator = EventCorrelator(
            window_seconds=window_seconds
        )

        # Keeps track of attacks that have already
        # been alerted.
        self.alerted_threats = set()

    def add_event(self, event):
        """
        Add a new event and analyze the current window.

        Returns:
            List of newly detected threats.
        """

        self.events.append(event)

        self._remove_old_events()

        findings = []

        # --------------------------------------------------
        # Existing detection rules
        # --------------------------------------------------

        findings.extend(
            detect_bruteforce(self.events)
        )

        findings.extend(
            detect_username_enumeration(self.events)
        )

        findings.extend(
            detect_success_after_failures(self.events)
        )

        findings.extend(
            detect_password_spraying(self.events)
        )

        findings.extend(
            detect_root_login(self.events)
        )

        # --------------------------------------------------
        # Enrich findings with IP classification.
        # --------------------------------------------------

        findings = enrich_findings(
            findings
        )

        # --------------------------------------------------
        # Correlate the current event window.
        # --------------------------------------------------

        correlated_activities = (
            self.correlator.correlate(
                self.events
            )
        )

        # --------------------------------------------------
        # Add correlation context to each finding.
        #
        # A finding is matched to the correlated activity
        # using source IP + target user.
        # --------------------------------------------------

        for finding in findings:

            matching_activity = None

            for activity in correlated_activities:

                if (
                    activity.source_ip
                    == finding.source_ip
                    and
                    activity.target_user
                    == finding.target_user
                ):
                    matching_activity = activity
                    break

            if matching_activity is None:
                continue

            finding.event_count = (
                matching_activity.event_count
            )

            finding.failed_attempts = (
                matching_activity.failed_attempts
            )

            finding.successful_attempts = (
                matching_activity.successful_attempts
            )

            finding.duration_seconds = (
                matching_activity.duration_seconds
            )

        # --------------------------------------------------
        # Remove duplicate alerts.
        # --------------------------------------------------

        new_findings = []

        for finding in findings:

            alert_key = (
                finding.attack_type,
                finding.source_ip,
                finding.target_user,
            )

            if alert_key in self.alerted_threats:
                continue

            self.alerted_threats.add(
                alert_key
            )

            new_findings.append(
                finding
            )

        return new_findings

    def _remove_old_events(self):
        """
        Remove events outside the rolling time window.
        """

        if not self.events:
            return

        newest_timestamp = (
            self.events[-1].timestamp
        )

        cutoff = (
            newest_timestamp
            - self.window
        )

        self.events = [
            event
            for event in self.events
            if event.timestamp >= cutoff
        ]