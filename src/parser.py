"""
AegisLog Log Parser

Responsible for reading raw authentication log entries
and converting supported events into structured AuthEvent objects.
"""

import re
from datetime import datetime

from models import AuthEvent


def parse_ssh_line(line):
    """Parse a single OpenSSH authentication log line."""

    line = line.strip()

    if not line:
        return None

    pattern = (
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"(?P<message>.+)$"
    )

    match = re.match(pattern, line)

    if not match:
        return None

    timestamp = match.group("timestamp")
    timestamp = datetime.strptime(
        timestamp,
        "%b %d %H:%M:%S"
    )
    hostname = match.group("hostname")
    pid = int(match.group("pid"))
    message = match.group("message")

    message_pattern = (
        r"(?P<status>Accepted|Failed)\s+password\s+for\s+"
        r"(?:(?:invalid user)\s+)?"
        r"(?P<username>\S+)\s+from\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"port\s+(?P<port>\d+)\s+"
        r"(?P<protocol>\S+)"
    )

    message_match = re.match(message_pattern, message)

    if not message_match:
        return None

    status = message_match.group("status").upper()
    username = message_match.group("username")
    source_ip = message_match.group("ip")
    source_port = int(message_match.group("port"))
    protocol = message_match.group("protocol")

    event = AuthEvent(
        timestamp=timestamp,
        hostname=hostname,
        service="sshd",
        pid=pid,
        status=status,
        username=username,
        source_ip=source_ip,
        source_port=source_port,
        protocol=protocol,
        invalid_user="invalid user" in message.lower(),
        raw_log=line,
    )

    return event

def parse_log_file(file_path):
    """
    Read a log file and convert supported SSH authentication
    entries into AuthEvent objects.
    """

    events = []

    try:

        with open(file_path, "r", encoding="utf-8") as file:

            for line in file:

                event = parse_ssh_line(line)

                if event:
                    events.append(event)

    except PermissionError:
        print(f"Error: Permission denied: {file_path}")
        return None

    except UnicodeDecodeError:
        print(f"Error: Unable to decode file: {file_path}")
        return None

    except OSError as error:
        print(f"Error: Unable to read file: {error}")
        return None

    return events

if __name__ == "__main__":
    test_log = (
        "Aug 06 10:16:03 web-server sshd[1901]: "
        "Failed password for root from 203.0.113.45 port 44321 ssh2"
    )

    events = parse_log_file("sample_logs/linux_auth.log")

    print(f"\nParsed {len(events)} authentication events.\n")

    for event in events:
        print(event)