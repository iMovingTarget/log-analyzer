from log_analyzer.parsers import PARSERS, AccessLogParser, SSHParser, detect_parser, extract_ip

# --- SSHParser ---


def test_ssh_failed_password():
    e = SSHParser().parse_line(
        "Jan 1 00:00:01 srv sshd[42]: Failed password for root from 203.0.113.7 port 22"
    )
    assert e is not None
    assert e.ip == "203.0.113.7"
    assert e.event_type == "failed"


def test_ssh_invalid_user():
    e = SSHParser().parse_line(
        "Jan 1 00:00:02 srv sshd[42]: Invalid user admin from 198.51.100.4 port 22"
    )
    assert e is not None
    assert e.event_type == "failed"


def test_ssh_accepted_password_and_publickey():
    p = SSHParser()
    for method in ("password", "publickey"):
        e = p.parse_line(f"Jan 1 00:00:03 srv sshd[42]: Accepted {method} for bob from 192.0.2.1")
        assert e is not None
        assert e.event_type == "accepted"


def test_ssh_no_ip():
    assert SSHParser().parse_line("some noise line with no address") is None


# --- AccessLogParser (nginx / Apache combined format) ---

LINE_200 = '203.0.113.1 - - [01/Jan/2024:00:00:01 +0000] "GET /index.html HTTP/1.1" 200 612'
LINE_404 = '198.51.100.9 - - [01/Jan/2024:00:00:02 +0000] "GET /secret HTTP/1.1" 404 162'
LINE_500 = '10.0.0.1 - - [01/Jan/2024:00:00:03 +0000] "POST /api HTTP/1.1" 500 88'


def test_access_200_accepted():
    e = AccessLogParser().parse_line(LINE_200)
    assert e is not None
    assert e.ip == "203.0.113.1"
    assert e.event_type == "accepted"
    assert e.extra["status"] == 200


def test_access_4xx_and_5xx_failed():
    p = AccessLogParser()
    assert p.parse_line(LINE_404).event_type == "failed"
    assert p.parse_line(LINE_500).event_type == "failed"


def test_access_malformed_request_line_still_parsed():
    # Scanners send garbage request lines; nginx logs them as "-" or raw bytes.
    e = AccessLogParser().parse_line('192.0.2.5 - - [01/Jan/2024:00:00:04 +0000] "-" 400 0')
    assert e is not None
    assert e.event_type == "failed"


def test_nginx_and_apache_are_aliases_for_access():
    assert PARSERS["nginx"] is AccessLogParser
    assert PARSERS["apache"] is AccessLogParser


# --- detect_parser ---


def test_detect_ssh():
    lines = [
        "Failed password for root from 203.0.113.7 port 22",
        "Invalid user admin from 198.51.100.4",
    ]
    assert isinstance(detect_parser(lines), SSHParser)


def test_detect_access_log():
    assert isinstance(detect_parser([LINE_200, LINE_404, LINE_500]), AccessLogParser)


def test_detect_is_not_fooled_by_sshd_in_a_url():
    # Regression: any line containing "sshd" used to switch a web log to SSH.
    lines = [
        '203.0.113.1 - - [01/Jan/2024:00:00:01 +0000] "GET /docs/sshd: HTTP/1.1" 200 612',
        LINE_404,
        LINE_500,
    ]
    assert isinstance(detect_parser(lines), AccessLogParser)


def test_detect_fallback_is_ssh():
    assert isinstance(detect_parser(["totally random noise"]), SSHParser)


# --- extract_ip ---


def test_extract_ip_ipv6():
    assert extract_ip("Failed password from 2001:db8::1 port 22") == "2001:db8::1"


def test_extract_ip_prefers_first_address():
    assert extract_ip("Connection from 203.0.113.7 (2001:db8::1)") == "203.0.113.7"


# --- timestamps ---


def test_bsd_syslog_time_infers_year_and_uses_local_zone():
    from datetime import datetime

    p = SSHParser(now=datetime(2026, 3, 1))
    e = p.parse_line("Feb  5 12:10:01 host sshd[1]: Failed password for root from 1.2.3.4")
    assert e.timestamp == datetime(2026, 2, 5, 12, 10, 1).astimezone()


def test_bsd_syslog_time_rolls_back_a_year_across_new_year():
    from datetime import datetime

    p = SSHParser(now=datetime(2026, 1, 2))
    e = p.parse_line("Dec 31 23:59:59 host sshd[1]: Failed password for root from 1.2.3.4")
    assert e.timestamp.year == 2025


def test_iso_syslog_time_keeps_its_offset():
    from datetime import datetime, timedelta, timezone

    e = SSHParser().parse_line(
        "2026-02-05T12:10:01.250000+01:00 host sshd[1]: Accepted publickey for bob from 1.2.3.4"
    )
    assert e.timestamp == datetime(
        2026, 2, 5, 12, 10, 1, 250000, tzinfo=timezone(timedelta(hours=1))
    )


def test_access_log_time_parsed():
    from datetime import datetime, timezone

    assert AccessLogParser().parse_line(LINE_200).timestamp == datetime(
        2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc
    )
