import sys
from pathlib import Path

from parser import parse_log_file
from detector import (
    detect_bruteforce,
    detect_username_enumeration,
    detect_success_after_failures,
    detect_password_spraying,
)



def main():

    if len(sys.argv) < 2:
        print("Usage: python src/main.py <log_file>")
        return

    log_path = Path(sys.argv[1])

    if not log_path.exists():
        print(f"Error: File not found: {log_path}")
        return

    if not log_path.is_file():
        print(f"Error: Not a file: {log_path}")
        return

    events = parse_log_file(log_path)

    if events is None:
        return

    if not events:
        print("No supported authentication events were found.")
        return
    
    findings = []
    
    findings.extend(detect_bruteforce(events))
    findings.extend(detect_username_enumeration(events))
    findings.extend(detect_success_after_failures(events))
    findings.extend(detect_password_spraying(events))


    print(f"\nEvents Parsed : {len(events)}")
    print(f"Threats Found : {len(findings)}\n")

    for finding in findings:

        print(f"Attack Type : {finding.attack_type}")
        print(f"Severity    : {finding.severity}")
        print(f"Source IP   : {finding.source_ip}")
        print(f"Target User : {finding.target_user}")
        print(f"Attempts    : {finding.attempts}")
        print(f"First Seen  : {finding.first_seen}")
        print(f"Last Seen   : {finding.last_seen}")
        print("-" * 50)


if __name__ == "__main__":
    main()