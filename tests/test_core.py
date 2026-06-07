from log_analyzer.core import extract_ip, is_failed, is_accepted, analyze_lines


def test_extract_ip_found():
    assert extract_ip("Failed password from 203.0.113.7 port 22") == "203.0.113.7"


def test_extract_ip_none():
    assert extract_ip("no ip here") is None


def test_classification():
    assert is_failed("Failed password for root from 1.2.3.4") is True
    assert is_failed("Invalid user admin from 1.2.3.4") is True
    assert is_failed("Accepted password for bob from 1.2.3.4") is False

    assert is_accepted("Accepted password for bob from 1.2.3.4") is True
    assert is_accepted("Failed password for root from 1.2.3.4") is False


def test_analyze_lines_counts_and_alerts():
    lines = [
        "Failed password for root from 203.0.113.7 port 22",
        "Invalid user admin from 203.0.113.7 port 22",
        "Accepted password for bob from 192.168.1.10 port 22",
        "Noise line without ip",
    ]

    report, ip_counter, failed_counter, accepted_counter = analyze_lines(
        lines, top=5, fail_threshold=1
    )

    assert report.total_lines == 4
    assert report.failed_total == 2
    assert report.accepted_total == 1

    assert ip_counter["203.0.113.7"] == 2
    assert failed_counter["203.0.113.7"] == 2
    assert accepted_counter["192.168.1.10"] == 1

    assert ("203.0.113.7", 2) in report.alerts


def test_min_events_filters_ips():
    lines = [
        "Failed password for invalid user root from 1.1.1.1 port 22",
        "Failed password for invalid user root from 2.2.2.2 port 22",
        "Accepted password for user ok from 2.2.2.2 port 22",
    ]
    report, ip_counter, failed_counter, accepted_counter = analyze_lines(
        lines, top=5, fail_threshold=1, min_events=2
    )

    assert "1.1.1.1" not in ip_counter
    assert ip_counter["2.2.2.2"] == 2

def test_extract_ip_invalid_octets():
    assert extract_ip("Connection from 999.0.0.1 port 22") is None
    assert extract_ip("Connection from 203.0.113.7 port 22") == "203.0.113.7