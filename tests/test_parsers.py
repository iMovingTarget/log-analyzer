from log_analyzer.parsers import PARSERS, AccessLogParser, SSHParser, detect_parser, extract_ip

# --- SSHParser ---


def test_ssh_failed_password():
    e = SSHParser().parse_line(
        "Jan 1 00:00:01 srv sshd[42]: Failed password for root from 203.0.113.7 port 22"
    )
    assert e is not None
    assert e.ip == "203.0.113.7"
    assert e.event_type == "failed"


def test_ssh_invalid_user_line_is_not_an_attempt_by_itself():
    # sshd logs it when the client names an unknown account; the attempt itself is the
    # "Failed ..." or pre-auth disconnect line that follows on the same connection.
    e = SSHParser().parse_line(
        "Jan 1 00:00:02 srv sshd[42]: Invalid user admin from 198.51.100.4 port 22"
    )
    assert e is not None
    assert (e.ip, e.event_type) == ("198.51.100.4", "other")
    assert e.extra == {"user": "admin", "port": 22, "invalid_user": True}


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


# --- SSH client address and fields (regression: the first IP-shaped token was used) ---


def test_ssh_username_cannot_frame_another_address():
    # Usernames are chosen by the client. An IP-shaped one used to be reported as the source.
    p = SSHParser()
    for line in (
        "Oct 28 16:10:01 vm sshd-session[1201]: Invalid user 10.9.8.7 from 203.0.113.5 port 4242",
        "Failed password for invalid user x from 10.9.8.7 port 22 from 203.0.113.5 port 4242 ssh2",
        "Failed password for 10.9.8.7 from 203.0.113.5 port 4242 ssh2",
        "Accepted password for 10.9.8.7 from 203.0.113.5 port 4242 ssh2",
    ):
        e = p.parse_line(line)
        assert e is not None and e.ip == "203.0.113.5", line


def test_ssh_tag_inside_a_username_is_not_a_header():
    e = SSHParser().parse_line("Invalid user sshd: from 203.0.113.5 port 4242")
    assert (e.ip, e.extra["user"]) == ("203.0.113.5", "sshd:")


def test_ssh_fields_are_extracted():
    e = SSHParser().parse_line(
        "2026-10-28T16:10:05+00:00 vm sshd-session[1205]: Failed publickey for sun"
        " from 2001:db8::7 port 64002 ssh2: ED25519 SHA256:abc"
    )
    assert (e.ip, e.event_type) == ("2001:db8::7", "failed")
    assert e.extra == {"user": "sun", "port": 64002, "method": "publickey"}


def test_ssh_journald_message_without_header():
    e = SSHParser().parse_line(
        "Accepted publickey for sun from 192.0.2.10 port 51122 ssh2: RSA-CERT SHA256:abc ID x"
    )
    assert (e.ip, e.event_type, e.extra["method"]) == ("192.0.2.10", "accepted", "publickey")


def test_ssh_rsyslog_repeated_message_is_unwrapped():
    e = SSHParser().parse_line(
        "Feb  5 12:10:01 host sshd[1]: message repeated 2 times: [ Failed password for root"
        " from 203.0.113.7 port 55222 ssh2]"
    )
    assert (e.ip, e.event_type, e.extra["user"]) == ("203.0.113.7", "failed", "root")


def test_ssh_unrecognised_line_is_other_with_its_first_address():
    e = SSHParser().parse_line(
        "Feb  5 12:10:01 host sshd[1]: Received disconnect from 203.0.113.7 port 55222:11: Bye"
    )
    assert (e.ip, e.event_type) == ("203.0.113.7", "other")


# --- SSH failures on servers without password logins (regression: classed as "other") ---
# Lines as logged by OpenSSH 10.2 (sshd-session) on a key-only server.


def test_ssh_preauth_disconnects_after_a_username_are_failures():
    p = SSHParser()
    for line, user in (
        ("Connection reset by authenticating user sun 203.0.113.5 port 63999 [preauth]", "sun"),
        ("Connection closed by authenticating user root 203.0.113.5 port 4 [preauth]", "root"),
        ("Connection reset by invalid user nwtest 203.0.113.5 port 63998 [preauth]", "nwtest"),
        ("Disconnected from invalid user admin 203.0.113.5 port 5 [preauth]", "admin"),
        (
            "Disconnecting authenticating user root 203.0.113.5 port 6:"
            " Too many authentication failures [preauth]",
            "root",
        ),
        (
            "error: maximum authentication attempts exceeded for invalid user a b"
            " from 203.0.113.5 port 7 ssh2 [preauth]",
            "a b",
        ),
    ):
        e = p.parse_line(line)
        assert (e.ip, e.event_type, e.extra["user"]) == ("203.0.113.5", "failed", user), line


def test_ssh_disconnects_without_a_login_attempt_are_not_failures():
    p = SSHParser()
    for line in (
        "Connection closed by 203.0.113.5 port 4 [preauth]",  # banner grab, no username sent
        "Disconnected from user sun 192.0.2.10 port 51122",  # end of a logged-in session
        "Received disconnect from 192.0.2.10 port 51122:11: disconnected by user",
    ):
        assert p.parse_line(line).event_type == "other", line


def test_ssh_preauth_username_cannot_frame_another_address():
    e = SSHParser().parse_line(
        "Connection closed by invalid user x 10.9.8.7 port 22 203.0.113.5 port 4242 [preauth]"
    )
    assert (e.ip, e.extra["user"], e.extra["port"]) == ("203.0.113.5", "x 10.9.8.7 port 22", 4242)


# --- Each SSH attempt counts once (regression: one attempt could count up to three times) ---


def _event_types(lines: list[str], parser: SSHParser | None = None) -> list[str]:
    parser = parser or SSHParser()
    return [parser.parse_line(line).event_type for line in lines]


def test_ssh_password_attempts_on_an_unknown_account_count_once_each():
    lines = [
        "Invalid user admin from 203.0.113.5 port 4000",
        "Failed password for invalid user admin from 203.0.113.5 port 4000 ssh2",
        "Failed password for invalid user admin from 203.0.113.5 port 4000 ssh2",
        "Connection closed by invalid user admin 203.0.113.5 port 4000 [preauth]",
    ]
    assert _event_types(lines) == ["other", "failed", "failed", "other"]


def test_ssh_key_only_attempt_on_an_unknown_account_counts_once():
    lines = [
        "Invalid user nwtest from 203.0.113.5 port 63998",
        "Connection reset by invalid user nwtest 203.0.113.5 port 63998 [preauth]",
    ]
    assert _event_types(lines) == ["other", "failed"]


def test_ssh_too_many_failures_counts_the_logged_attempts_only():
    lines = [
        "Failed publickey for root from 203.0.113.5 port 5000 ssh2: ED25519 SHA256:a",
        "Failed publickey for root from 203.0.113.5 port 5000 ssh2: ED25519 SHA256:b",
        "error: maximum authentication attempts exceeded for root from 203.0.113.5 port 5000"
        " ssh2 [preauth]",
        "Disconnecting authenticating user root 203.0.113.5 port 5000:"
        " Too many authentication failures [preauth]",
    ]
    assert _event_types(lines) == ["failed", "failed", "other", "other"]


def test_ssh_attempt_limit_without_logged_failures_counts_once():
    lines = [
        "error: maximum authentication attempts exceeded for root from 203.0.113.5 port 5001"
        " ssh2 [preauth]",
        "Disconnecting authenticating user root 203.0.113.5 port 5001:"
        " Too many authentication failures [preauth]",
    ]
    assert _event_types(lines) == ["failed", "other"]


def test_ssh_connections_are_told_apart_by_address_and_port():
    lines = [
        "Failed password for root from 203.0.113.5 port 4000 ssh2",
        "Connection closed by authenticating user root 203.0.113.5 port 4001 [preauth]",
        "Connection closed by authenticating user root 198.51.100.5 port 4000 [preauth]",
        "Connection closed by authenticating user root 203.0.113.5 port 4000 [preauth]",
        # The port is free again: a new connection on it is a new attempt.
        "Connection closed by authenticating user root 203.0.113.5 port 4000 [preauth]",
    ]
    assert _event_types(lines) == ["failed", "failed", "failed", "other", "failed"]


def test_ssh_reset_forgets_connections():
    # Regression guard: the CLI reads the same lines twice (report, then SIEM events) with
    # one parser; without a reset the second pass would count differently.
    parser = SSHParser()
    lines = [
        "Failed password for root from 203.0.113.5 port 4000 ssh2",
        "Connection closed by authenticating user root 203.0.113.5 port 4002 [preauth]",
    ]
    _event_types(lines[:1], parser)
    parser.reset()
    assert _event_types(lines[1:], parser) == ["failed"]


def test_ssh_tracked_connections_are_bounded():
    parser = SSHParser()
    parser.max_tracked_connections = 2
    _event_types(
        [f"Failed password for root from 203.0.113.5 port {p} ssh2" for p in (1, 2, 3)], parser
    )
    # Port 1 was forgotten, so its disconnect counts; port 3 is still remembered.
    assert _event_types(
        [
            "Connection closed by authenticating user root 203.0.113.5 port 1 [preauth]",
            "Connection closed by authenticating user root 203.0.113.5 port 3 [preauth]",
        ],
        parser,
    ) == ["failed", "other"]
