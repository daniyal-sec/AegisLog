"""
AegisLog Report Generator Tests

Tests generation of human-readable investigation reports
with correlation context.
"""

import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from models import ThreatFinding
from report_generator import generate_report, save_report


def create_finding():
    """Create a synthetic correlated threat finding."""

    return ThreatFinding(
        attack_type="Authentication Brute Force",
        severity="HIGH",
        source_ip="192.168.1.50",
        target_user="TEST_USER",
        attempts=5,
        service="Windows Authentication",
        first_seen=datetime(2026, 8, 12, 14, 30, 0),
        last_seen=datetime(2026, 8, 12, 14, 30, 20),
        recommendation="Investigate source IP immediately.",
        ip_classification="Private",
        event_count=5,
        failed_attempts=5,
        successful_attempts=0,
        duration_seconds=20.0,
    )


def test_report_contains_analysis_summary():
    """Verify the report contains the main analysis summary."""

    finding = create_finding()

    report = generate_report(
        events=[object()] * 5,
        findings=[finding],
        log_file="test_windows.log",
    )

    assert "AEGISLOG SECURITY REPORT" in report
    assert "Events Parsed : 5" in report
    assert "Threats Found : 1" in report


def test_report_contains_threat_details():
    """Verify threat information appears in the report."""

    finding = create_finding()

    report = generate_report(
        events=[object()] * 5,
        findings=[finding],
        log_file="test_windows.log",
    )

    assert "AUTHENTICATION BRUTE FORCE" in report
    assert "Severity    : HIGH" in report
    assert "Source IP   : 192.168.1.50" in report
    assert "Target User : TEST_USER" in report
    assert "Attempts    : 5" in report
    assert "IP Type     : Private" in report


def test_report_contains_correlation_context():
    """Verify correlation fields appear in the investigation report."""

    finding = create_finding()

    report = generate_report(
        events=[object()] * 5,
        findings=[finding],
        log_file="test_windows.log",
    )

    assert "Events      : 5" in report
    assert "Failed      : 5" in report
    assert "Successful  : 0" in report
    assert "Duration    : 20.0 seconds" in report


def test_report_contains_timestamps():
    """Verify first and last seen timestamps are formatted."""

    finding = create_finding()

    report = generate_report(
        events=[object()] * 5,
        findings=[finding],
        log_file="test_windows.log",
    )

    assert "First Seen  : Aug 12 14:30:00" in report
    assert "Last Seen   : Aug 12 14:30:20" in report


def test_empty_findings_report():
    """Verify a clean report when no threats are detected."""

    report = generate_report(
        events=[],
        findings=[],
        log_file="clean.log",
    )

    assert "Events Parsed : 0" in report
    assert "Threats Found : 0" in report
    assert "No threats detected." in report


def test_save_report(tmp_path):
    """Verify reports can be written to disk."""

    finding = create_finding()

    report = generate_report(
        events=[object()] * 5,
        findings=[finding],
        log_file="test_windows.log",
    )

    output_file = tmp_path / "test_report.txt"

    save_report(
        report,
        output_file,
    )

    assert output_file.exists()

    saved_content = output_file.read_text(
        encoding="utf-8"
    )

    assert saved_content == report