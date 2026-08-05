from parser import parse_log_file
from detector import (
    detect_bruteforce,
    detect_username_enumeration,
)


def main():

    events = parse_log_file("sample_logs/linux_auth.log")

    findings = []
    
    findings.extend(detect_bruteforce(events))
    findings.extend(detect_username_enumeration(events))


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