"""
AegisLog Utility Function Tests

Tests IP classification and finding enrichment helpers.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from utils import classify_ip


def test_local_ip_classification():
    """Verify normalized local authentication is classified as Local."""

    assert classify_ip("local") == "Local"


def test_loopback_ip_classification():
    """Verify IPv4 loopback addresses are classified correctly."""

    assert classify_ip("127.0.0.1") == "Loopback"


def test_private_ip_classification():
    """Verify RFC1918 private addresses are classified correctly."""

    assert classify_ip("192.168.1.50") == "Private"
    assert classify_ip("10.0.0.5") == "Private"
    assert classify_ip("172.16.0.10") == "Private"


def test_documentation_ip_classification():
    """Verify TEST-NET documentation ranges."""

    assert classify_ip("192.0.2.50") == "Documentation"
    assert classify_ip("198.51.100.27") == "Documentation"
    assert classify_ip("203.0.113.45") == "Documentation"


def test_public_ip_classification():
    """Verify public addresses are classified correctly."""

    assert classify_ip("8.8.8.8") == "Public"


def test_reserved_ip_classification():
    """Verify reserved addresses are classified correctly."""

    assert classify_ip("240.0.0.1") == "Reserved"


def test_invalid_ip_classification():
    """Verify invalid addresses are rejected safely."""

    assert classify_ip("invalid-ip") == "Invalid"