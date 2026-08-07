"""
AegisLog Detection Engine

Responsible for analyzing parsed authentication events
and extracting security findings.
"""

from collections import defaultdict
from models import ThreatFinding

def detect_bruteforce(events, threshold=5, time_window=60):
    """
    Detect brute-force attacks.
    """

    grouped_events = defaultdict(list)

    for event in events:

        if event.status != "FAILED":
            continue

        key = (event.source_ip, event.username) 

        grouped_events[key].append(event)

    findings = []

    for(ip, username), attempts in grouped_events.items():

        attempts.sort(key=lambda event: event.timestamp)
        if len(attempts) < threshold:
            continue

        time_difference = (
        attempts[-1].timestamp - attempts[0].timestamp
        ).total_seconds()

        if time_difference > time_window:
            continue

        findings.append(
            ThreatFinding(
                attack_type="SSH Brute Force",

                severity="HIGH",

                source_ip=ip,

                target_user=username,

                attempts=len(attempts),

                service=attempts[0].service,

                first_seen=attempts[0].timestamp,

                last_seen=attempts[-1].timestamp,

                recommendation="Investigate source IP immediately."
            )
        )
    return findings

def detect_username_enumeration(events, threshold=3, time_window=60,):
    """
    Detect username enumeration attacks.

    Same IP trying multiple invalid usernames.
    """

    grouped_events = defaultdict(list)

    for event in events:

        if not event.invalid_user:
            continue

        grouped_events[event.source_ip].append(event)

    findings = []

    for ip, attempts in grouped_events.items():

        attempts.sort(key=lambda event: event.timestamp)

        usernames = {event.username for event in attempts}

        if len(usernames) < threshold:
            continue

        time_difference = (
            attempts[-1].timestamp - attempts[0].timestamp
        ).total_seconds()

        if time_difference > time_window:
            continue

        findings.append(

            ThreatFinding(

                attack_type="Username Enumeration",

                severity="MEDIUM",

                source_ip=ip,

                target_user=", ".join(sorted(usernames)),

                attempts=len(attempts),

                service=attempts[0].service,

                first_seen=attempts[0].timestamp,

                last_seen=attempts[-1].timestamp,

                recommendation="Investigate repeated invalid username attempts."
            )
        )
    return findings

def detect_success_after_failures(events, threshold=3, time_window=60):
    """
    Detect a successful login after multiple failed attempts
    from the same source IP and username.
    """

    grouped_events = defaultdict(list)

    # Group events using both source IP and username.

    for event in events:
        key = (event.source_ip, event.username)
        grouped_events[key].append(event)

    findings = []

    # Analyze each IP + username combination separately.

    for(ip, username), event_list in grouped_events.items():

        event_list.sort(key=lambda event: event.timestamp)

        failed_count = 0
        first_failure = None

        for event in event_list:

            if event.status == "FAILED":
                failed_count += 1

                if first_failure is None:
                    first_failure = event

            elif event.status == "ACCEPTED" and failed_count >= threshold:

                time_difference = (
                    event.timestamp - first_failure.timestamp
                ).total_seconds()

                if time_difference > time_window:
                    continue

                findings.append(
                    ThreatFinding(
                        attack_type="Successful login after multiple failures",
                        severity="CRITICAL",
                        source_ip=ip,
                        target_user=username,
                        attempts=failed_count,
                        service=event.service,
                        first_seen=first_failure.timestamp,
                        last_seen=event.timestamp,
                        recommendation=(
                            "Verify whether the successful login is legitimate "
                            "and investigate the source IP immediately."
                        ),
                    )
                )

                break
    return findings



def detect_password_spraying(events, threshold=4, time_window=60,):
    """
    Detect possible password spraying activity.

    A password spray is identified when the same source IP
    generates failed authentication attempts against multiple
    different usernames.
    """

    grouped_events = defaultdict(list)

    # Collect failed authentication events by source IP.

    for event in events:

        if event.status != "FAILED":
            continue

        grouped_events[event.source_ip].append(event)

    findings = []

    # Analyze the failed attempts generated by each IP.

    for ip, attempts in grouped_events.items():

        attempts.sort(key=lambda event: event.timestamp)
        
        usernames = {event.username for event in attempts}

        if len(usernames) < threshold:
            continue
        time_difference = (
        attempts[-1].timestamp - attempts[0].timestamp
        ).total_seconds()

        if time_difference > time_window:
            continue

        findings.append(
            ThreatFinding(
                attack_type="Password Spraying",
                severity="HIGH",
                source_ip=ip,
                target_user=", ".join(sorted(usernames)),
                attempts=len(attempts),
                service=attempts[0].service,
                first_seen=attempts[0].timestamp,
                last_seen=attempts[-1].timestamp,
                recommendation=(
                    "Investigate the source IP and targeted accounts "
                    "for possible password spraying activity."
                ),
            )
        )



    return findings