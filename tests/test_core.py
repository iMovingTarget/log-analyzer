from log_analyzer.core import RateTracker, analyze_lines
from log_analyzer.parsers import SSHParser, extract_ip


def test_rate_tracker_fires_at_limit():
    rt = RateTracker(window_seconds=60, max_events=3)
    assert rt.record("1.2.3.4") is False
    assert rt.record("1.2.3.4") is False
    assert rt.record("1.2.3.4") is True


def test_rate_tracker_independent_ips():
    rt = RateTracker(window_seconds=60, max_events=2)
    rt.record("1.1.1.1")
    rt.record("1.1.1.1")
    assert rt.record("2.2.2.2") is False


def test_extract_ip_found():
    assert extract_ip("Failed password from 203.0.113.7 port 22") == "203.0.113.7"


def test_extract_ip_none():
    assert extract_ip("no ip here") is None


def test_classification():
    kind = lambda line: SSHParser().parse_line(line).event_type  # noqa: E731

    assert kind("Failed password for root from 1.2.3.4") == "failed"
    # The attempt is counted by the line that follows (Failed ... or the pre-auth disconnect).
    assert kind("Invalid user admin from 1.2.3.4") == "other"
    assert kind("Accepted password for bob from 1.2.3.4") == "accepted"
    assert kind("Accepted publickey for bob from 1.2.3.4") == "accepted"
    assert kind("Connection closed by 1.2.3.4 port 22") == "other"


def test_analyze_lines_counts_and_alerts():
    lines = [
        "Failed password for root from 203.0.113.7 port 22",
        "Invalid user admin from 203.0.113.7 port 23",
        "Connection closed by invalid user admin 203.0.113.7 port 23 [preauth]",
        "Accepted password for bob from 192.168.1.10 port 22",
        "Noise line without ip",
    ]

    report, ip_counter, failed_counter, accepted_counter = analyze_lines(
        lines, top=5, fail_threshold=1
    )

    assert report.total_lines == 5
    assert report.failed_total == 2
    assert report.accepted_total == 1

    assert ip_counter["203.0.113.7"] == 3
    assert failed_counter["203.0.113.7"] == 2
    assert accepted_counter["192.168.1.10"] == 1

    assert ("203.0.113.7", 2) in report.alerts


def test_min_events_filters_ips():
    lines = [
        "Failed password for invalid user root from 1.1.1.1 port 22",
        "Failed password for invalid user root from 2.2.2.2 port 22",
        "Accepted password for user ok from 2.2.2.2 port 22",
    ]
    _report, ip_counter, _failed_counter, _accepted_counter = analyze_lines(
        lines, top=5, fail_threshold=1, min_events=2
    )

    assert "1.1.1.1" not in ip_counter
    assert ip_counter["2.2.2.2"] == 2


def test_extract_ip_invalid_octets():
    assert extract_ip("Connection from 999.0.0.1 port 22") is None
    assert extract_ip("Connection from 203.0.113.7 port 22") == "203.0.113.7"


def test_blocklisted_successful_login_is_kept_and_critical():
    # Regression: blocklisted IPs had every event rewritten to "failed", which
    # hid the one event that matters most -- a known-bad IP getting in.
    lines = [
        "Failed password for root from 6.6.6.6 port 22",
        "Accepted password for root from 6.6.6.6 port 22",
    ]
    report, _, failed, accepted = analyze_lines(
        lines, top=5, fail_threshold=10, blocklist={"6.6.6.6"}
    )

    assert failed["6.6.6.6"] == 1
    assert accepted["6.6.6.6"] == 1
    assert report.blocklisted == [("6.6.6.6", 2)]
    assert report.blocklisted_logins == ["6.6.6.6"]
    assert report.severity == "CRITICAL"


def test_blocklisted_ip_is_reported_below_threshold_and_min_events():
    lines = [
        "Failed password for root from 6.6.6.6 port 22",
        "Failed password for root from 1.1.1.1 port 22",
        "Failed password for root from 1.1.1.1 port 22",
    ]
    report, ips, _, _ = analyze_lines(
        lines, top=5, fail_threshold=10, min_events=2, blocklist={"6.6.6.6"}
    )

    assert "6.6.6.6" in ips  # survives --min-events
    assert report.blocklisted == [("6.6.6.6", 1)]
    assert report.blocklisted_logins == []
    assert report.severity == "WARNING"


def test_allowlisted_ip_is_dropped():
    lines = ["Failed password for root from 10.0.0.1 port 22"] * 5
    report, ips, _, _ = analyze_lines(lines, top=5, fail_threshold=1, allowlist={"10.0.0.1"})

    assert not ips
    assert report.alerts == []


def test_rate_tracker_window_expires_old_events():
    from datetime import datetime, timedelta, timezone

    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rt = RateTracker(window_seconds=60, max_events=3)
    rt.record("1.2.3.4", now=t0)
    rt.record("1.2.3.4", now=t0 + timedelta(seconds=1))
    # The first two events are outside the 60 s window by now.
    assert rt.record("1.2.3.4", now=t0 + timedelta(seconds=62)) is False


def test_rate_tracker_forgets_idle_ips():
    # Regression: eviction ran right after an append, so it never fired and
    # every IP ever seen stayed in memory for the life of --watch.
    from datetime import datetime, timedelta, timezone

    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rt = RateTracker(window_seconds=60, max_events=5)
    for i in range(1000):
        rt.record(f"10.0.{i // 256}.{i % 256}", now=t0)
    assert rt.tracked_ips() == 1000

    rt.record("192.0.2.1", now=t0 + timedelta(seconds=61))
    assert rt.tracked_ips() == 1


def test_analyze_lines_and_siem_events_agree_when_sharing_a_parser():
    # The CLI passes one parser to both; parser state must not leak between the passes.
    from log_analyzer.siem import build_siem_events

    lines = [
        "Failed password for root from 203.0.113.7 port 40 ssh2",
        "Connection closed by authenticating user root 203.0.113.7 port 40 [preauth]",
        "Connection closed by authenticating user root 203.0.113.7 port 41 [preauth]",
    ]
    parser = SSHParser()
    report, *_ = analyze_lines(lines, top=5, fail_threshold=1, parser=parser)
    events = build_siem_events(lines, parser, "auth.log", 1)
    assert report.failed_total == 2
    assert [e.event_type for e in events] == ["failed", "other", "failed"]
