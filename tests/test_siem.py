from log_analyzer.siem import build_siem_events, SIEMEvent
from log_analyzer.parsers import SSHParser


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


def test_siem_event_severity_reflects_threshold():
    lines = ["Failed password for root from 1.2.3.4 port 22"]
    events = build_siem_events(lines, SSHParser(), "auth.log", fail_threshold=10)
    assert events[0].severity == "INFO"  # single event, well under threshold of 10


def test_siem_event_has_all_fields():
    lines = ["Failed password for root from 1.2.3.4 port 22"]
    events = build_siem_events(lines, SSHParser(), "auth.log", fail_threshold=3)
    e = events[0]
    assert e.timestamp and e.log_file == "auth.log" and e.raw_log