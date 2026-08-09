from datetime import datetime
import sys
from pathlib import Path
from report_generator import generate_report, save_report
from parser import parse_log_file
from detector import (
    detect_bruteforce,
    detect_username_enumeration,
    detect_success_after_failures,
    detect_password_spraying,
    detect_root_login,
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
    findings.extend(detect_root_login(events))


    report = generate_report(events, findings, log_path.name)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    report_path = Path("reports") / f"report_{timestamp}.txt"

    save_report(report, report_path)

    print()
    print(report) 

    print()
    print(f"Report saved to: {report_path}")  


if __name__ == "__main__":
    main()