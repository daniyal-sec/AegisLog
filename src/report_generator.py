"""
AegisLog Report Generator

Responsible for generating human-readable
security investigation reports.
"""

from datetime import datetime

def generate_report(events, findings, log_file):
    """
    Generate a human-readable security investigation report.

    Returns:
        str: Formatted report ready for display or saving.
    """

    report = []

    # ==========================
    # Report Header
    # ==========================
    report.append("=" * 50)
    report.append("              AEGISLOG SECURITY REPORT")
    report.append("=" * 50)
    report.append("")

    report.append(
        f"Generated on : {datetime.now().strftime('%b %d %Y %H:%M:%S')}"
    )

    report.append(f"Log File     : {log_file}")
    report.append("")

    # ==========================
    # Analysis Summary
    # ==========================
    report.append("ANALYSIS SUMMARY")
    report.append("=" * 50)
    report.append(f"Events Parsed : {len(events)}")
    report.append(f"Threats Found : {len(findings)}")
    report.append("")

    # ==========================
    # Threat Severity Summary
    # ==========================
    critical = 0
    high = 0
    medium = 0
    low = 0

    for finding in findings:

        if finding.severity == "CRITICAL":
            critical += 1

        elif finding.severity == "HIGH":
            high += 1

        elif finding.severity == "MEDIUM":
            medium += 1

        elif finding.severity == "LOW":
            low += 1

    report.append("THREAT SEVERITY")
    report.append("=" * 50)
    report.append(f"Critical : {critical}")
    report.append(f"High     : {high}")
    report.append(f"Medium   : {medium}")
    report.append(f"Low      : {low}")
    report.append("")

    # ==========================
    # Threat Details
    # ==========================
    report.append("DETECTED THREATS")
    report.append("-" * 50)
    report.append("")

    if not findings:
        report.append("No threats detected.")
        report.append("")
    else:
        for index, finding in enumerate(findings, start=1):

            report.append(
            f"[{index}] {finding.attack_type.upper()}"
    )

            report.append("-" * 50)

            report.append(f"Severity    : {finding.severity}")
            report.append(f"Source IP   : {finding.source_ip}")
            report.append(f"Target User : {finding.target_user}")
            report.append(f"Attempts    : {finding.attempts}")

            report.append(
            f"First Seen  : {finding.first_seen.strftime('%b %d %H:%M:%S')}"
        )

            report.append(
            f"Last Seen   : {finding.last_seen.strftime('%b %d %H:%M:%S')}"
        )

            report.append("Recommendation")
            report.append(f"  {finding.recommendation}")

            report.append("")
            report.append("-" * 50)
            report.append("")

    return "\n".join(report)

def save_report(report, output_path):

    """
    Save a generated report to a text file.

    Args:
        report: Generated report string.
        output_path: Destination file path.
    """

    try:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(report)

    except OSError as error:
        print(f"Error: Unable to save report: {error}")

        