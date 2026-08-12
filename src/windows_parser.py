"""
AegisLog Windows Event Parser

Converts Windows Security Event Log 4624/4625
events into the normalized AuthEvent model.
"""

import ipaddress

from models import AuthEvent


SUCCESSFUL_LOGON = 4624
FAILED_LOGON = 4625


def get_event_field(event, index):
    """Safely retrieve a field from a Windows event."""

    if not event.StringInserts:
        return ""

    if index >= len(event.StringInserts):
        return ""

    value = event.StringInserts[index]

    if value is None:
        return ""

    return str(value).strip()


def classify_ip(source_ip, logon_type):
    """Classify the source IP of a Windows authentication."""

    if not source_ip or source_ip in ("-", "::", ""):
        if logon_type in ("2", "7", "11"):
            return "local"

        return "unknown"

    try:
        ip = ipaddress.ip_address(source_ip)

        if ip.is_loopback:
            return "loopback"

        if ip.is_private:
            return "private"

        if ip.is_reserved:
            return "reserved"

        return "public"

    except ValueError:
        return "unknown"


def parse_windows_event(event):
    """
    Convert a Windows 4624/4625 event into an AuthEvent.

    Returns:
        AuthEvent: Normalized authentication event.
        None: Irrelevant Windows event.
    """

    event_id = event.EventID & 0xFFFF

    if event_id not in (
        SUCCESSFUL_LOGON,
        FAILED_LOGON,
    ):
        return None

    # Windows may report the target username as "-"
    # for local authentication failures. In that case,
    # fall back to the subject username.

    target_username = get_event_field(event, 5)
    subject_username = get_event_field(event, 1)

    username = (
    target_username
    if target_username and target_username != "-"
    else subject_username
)

    # Windows Security 4624/4625:
    # Field 10 = Logon Type
    # Field 19 = Source IP
    # Field 20 = Source Port
    logon_type = get_event_field(event, 10)

    source_ip = get_event_field(event, 19)
    source_port = get_event_field(event, 20)

    # Ignore service logons.
    if logon_type == "5":
        return None

    # Ignore events without a username.
    if not username or username == "-":
        return None

    # Windows may report local authentication without
    # providing a remote source address.
    if source_ip in (
    "-",
    "",
    "::",
    "::1",
    "127.0.0.1",
):
        source_ip = "local"

    try:
        source_port = int(source_port)
    except (ValueError, TypeError):
        source_port = 0

    status = (
        "SUCCESS"
        if event_id == SUCCESSFUL_LOGON
        else "FAILED"
    )

    return AuthEvent(
        timestamp=event.TimeGenerated,
        hostname="Windows",
        service="Windows Authentication",
        pid=0,
        status=status,
        username=username,
        source_ip=source_ip,
        source_port=source_port,
        protocol="Windows Security",
        invalid_user=False,
        raw_log=(
            f"Windows Event {event_id} | "
            f"User={username} | "
            f"Source={source_ip} | "
            f"LogonType={logon_type}"
        ),
    )