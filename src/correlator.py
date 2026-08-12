"""
AegisLog Event Correlator

Groups authentication events into related activity
based on source IP, username, and a configurable
time window.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class CorrelatedActivity:
    """Represents a group of related authentication events."""

    source_ip: str
    target_user: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    failed_attempts: int
    successful_attempts: int


class EventCorrelator:
    """
    Correlates authentication events that belong to the
    same source IP and target account within a time window.
    """

    def __init__(self, window_seconds=60):
        self.window = timedelta(seconds=window_seconds)

    def correlate(self, events):
        """
        Group related authentication events.

        Events are grouped by:

            source_ip + username

        Only events occurring within the configured
        time window are considered part of the same
        activity.
        """

        if not events:
            return []

        grouped = {}

        for event in events:

            key = (
                event.source_ip,
                event.username,
            )

            grouped.setdefault(key, []).append(event)

        activities = []

        for (source_ip, username), event_list in grouped.items():

            event_list.sort(
                key=lambda event: event.timestamp
            )

            current_group = []

            for event in event_list:

                if not current_group:
                    current_group = [event]
                    continue

                first_timestamp = (
                    current_group[0].timestamp
                )

                if (
                    event.timestamp - first_timestamp
                    <= self.window
                ):
                    current_group.append(event)

                else:
                    activities.append(
                        self._create_activity(
                            source_ip,
                            username,
                            current_group,
                        )
                    )

                    current_group = [event]

            if current_group:
                activities.append(
                    self._create_activity(
                        source_ip,
                        username,
                        current_group,
                    )
                )

        activities.sort(
            key=lambda activity: activity.first_seen
        )

        return activities

    @staticmethod
    def _create_activity(
        source_ip,
        username,
        events,
    ):
        """Convert a group of events into CorrelatedActivity."""

        first_seen = events[0].timestamp
        last_seen = events[-1].timestamp

        failed_attempts = sum(
            1
            for event in events
            if event.status == "FAILED"
        )

        successful_attempts = sum(
            1
            for event in events
            if event.status in ("SUCCESS", "ACCEPTED")
        )

        duration_seconds = (
            last_seen - first_seen
        ).total_seconds()

        return CorrelatedActivity(
            source_ip=source_ip,
            target_user=username,
            event_count=len(events),
            first_seen=first_seen,
            last_seen=last_seen,
            duration_seconds=duration_seconds,
            failed_attempts=failed_attempts,
            successful_attempts=successful_attempts,
        )