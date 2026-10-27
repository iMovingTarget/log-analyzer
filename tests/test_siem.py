from log_analyzer.parsers import AccessLogParser, SSHParser
from log_analyzer.siem import build_siem_events


def _severities(lines, threshold, **kw):
    return [e.severity for e in build_siem_events(lines, SSHParser(), "auth.log", threshold, **kw)]


def test_build_siem_events_basic():
    lines = [
        "Failed password for root from 203.0.113.7 port 22",
        "Accepted password for bob from 192.168.1.10 port 22",
        "noise line with no ip",
    ]
    events = build_siem_events(lines, SSHParser(), "auth.log", fail_threshold=3)

    assert len(events) == 2  # noise line is skipped
    assert events[0].source_ip == "203.0.113.7"
    assert events[0].event_type == "failed"
    assert events[1].event_type == "accepted"


def test_single_failure_under_threshold_is_info():
    assert _severities(["Failed password for root from 1.2.3.4 port 22"], 10) == ["INFO"]


def test_severity_escalates_per_ip_as_failures_accumulate():
    # Regression: every event used to be INFO, whatever the IP had done before.
    lines = ["Failed password for root from 1.2.3.4 port 22"] * 9
    assert _severities(lines, 3) == ["INFO"] * 2 + ["WARNING"] * 6 + ["CRITICAL"]


def test_failures_are_counted_per_ip():
    lines = [
        "Failed password for root from 1.1.1.1 port 22",
        "Failed password for root from 2.2.2.2 port 22",
    ]
    assert _severities(lines, 2) == ["INFO", "INFO"]


def test_login_after_brute_force_is_critical():
    lines = ["Failed password for root from 1.2.3.4 port 22"] * 3 + [
        "Accepted password for root from 1.2.3.4 port 22"
    ]
    events = build_siem_events(lines, SSHParser(), "auth.log", fail_threshold=3)

    assert events[-1].severity == "CRITICAL"
    assert "after 3 failures" in events[-1].reason


def test_blocklisted_login_is_critical():
    lines = ["Accepted publickey for root from 6.6.6.6 port 22"]
    assert _severities(lines, 3, blocklist={"6.6.6.6"}) == ["CRITICAL"]


def test_timestamp_comes_from_the_log_line_in_utc():
    # Regression: every event carried the same ingest time instead of its own.
    lines = [
        '203.0.113.1 - - [01/Jan/2024:00:00:01 +0200] "GET / HTTP/1.1" 401 0',
        '203.0.113.1 - - [01/Jan/2024:00:00:05 +0200] "GET / HTTP/1.1" 401 0',
    ]
    events = build_siem_events(lines, AccessLogParser(), "access.log", fail_threshold=3)

    assert [e.timestamp for e in events] == [
        "2023-12-31T22:00:01+00:00",
        "2023-12-31T22:00:05+00:00",
    ]
    assert events[0].ingested_at != events[0].timestamp


def test_unparseable_time_falls_back_to_ingest_time():
    events = build_siem_events(
        ["Failed password for root from 1.2.3.4 port 22"], SSHParser(), "auth.log", 3
    )
    assert events[0].timestamp == events[0].ingested_at
