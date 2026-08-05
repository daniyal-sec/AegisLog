"""
AegisLog Detection Engine

Responsible for analyzing parsed authentication events
and extracting security findings.
"""

from collections import defaultdict
from models import ThreatFinding

def detect_bruteforce(events, threshold=5):
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

        if len(attempts) < threshold:
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

def detect_username_enumeration(events, threshold=3):
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

        usernames = {event.username for event in attempts}

        if len(usernames) < threshold:
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