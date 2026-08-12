"""
AegisLog Utility Functions

Provides reusable helper functions used throughout AegisLog.
"""

import ipaddress


def classify_ip(ip_address):
    """
    Classify an IP address for security reporting.

    Returns:
        str: IP classification.
    """

    if ip_address == "local":
        return "Local"

    try:
        ip = ipaddress.ip_address(ip_address)

    except ValueError:
        return "Invalid"

    # Loopback
    if ip.is_loopback:
        return "Loopback"

    # Documentation / TEST-NET ranges
    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    for network in documentation_networks:
        if ip in network:
            return "Documentation"

    # RFC1918 private networks
    private_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    for network in private_networks:
        if ip in network:
            return "Private"

    # Other special/reserved addresses
    if ip.is_reserved:
        return "Reserved"

    # Everything else
    return "Public"


def enrich_findings(findings):
    """
    Add IP classification information to detected threats.

    Args:
        findings: List of ThreatFinding objects.

    Returns:
        List of enriched ThreatFinding objects.
    """

    for finding in findings:
        finding.ip_classification = classify_ip(finding.source_ip)

    return findings


if __name__ == "__main__":

    test_ips = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.10",
    "127.0.0.1",
    "192.0.2.50",
    "198.51.100.27",
    "203.0.113.45",
    "8.8.8.8",
    "invalid-ip",
]

    for ip in test_ips:
        print(f"{ip} -> {classify_ip(ip)}")