from log_analyzer.parsers import (
    SSHParser, NginxParser,
    detect_parser,
)


# --- SSHParser ---

def test_ssh_failed_password():
    p = SSHParser()
    e = p.parse_line("Jan 1 00:00:01 srv sshd: Failed password for root from 203.0.113.7 port 22")
    assert e is not None
    assert e.ip == "203.0.113.7"
    assert e.event_type == "failed"

def test_ssh_invalid_user():
    p = SSHParser()
    e = p.parse_line("Jan 1 00:00:02 srv sshd: Invalid user admin from 198.51.100.4 port 22")
    assert e is not None
    assert e.event_type == "failed"

def test_ssh_accepted():
    p = SSHParser()
    e = p.parse_line("Jan 1 00:00:03 srv sshd: Accepted password for bob from 192.168.1.1 port 22")
    assert e is not None
    assert e.event_type == "accepted"

def test_ssh_no_ip():
    p = SSHParser()
    assert p.parse_line("some noise line with no address") is None


# --- NginxParser ---

NGINX_LINE_200 = '203.0.113.1 - - [01/Jan/2024:00:00:01 +0000] "GET /index.html HTTP/1.1" 200 612'
NGINX_LINE_404 = '198.51.100.9 - - [01/Jan/2024:00:00:02 +0000] "GET /secret HTTP/1.1" 404 162'
NGINX_LINE_500 = '10.0.0.1 - - [01/Jan/2024:00:00:03 +0000] "POST /api HTTP/1.1" 500 88'

def test_nginx_200_accepted():
    p = NginxParser()
    e = p.parse_line(NGINX_LINE_200)
    assert e is not None
    assert e.ip == "203.0.113.1"
    assert e.event_type == "accepted"
    assert e.extra["status"] == 200

def test_nginx_404_failed():
    p = NginxParser()
    e = p.parse_line(NGINX_LINE_404)
    assert e is not None
    assert e.event_type == "failed"

def test_nginx_500_failed():
    p = NginxParser()
    e = p.parse_line(NGINX_LINE_500)
    assert e is not None
    assert e.event_type == "failed"


# --- detect_parser ---

def test_detect_ssh():
    lines = [
        "Failed password for root from 203.0.113.7 port 22",
        "Invalid user admin from 198.51.100.4",
    ]
    assert isinstance(detect_parser(lines), SSHParser)

def test_detect_nginx():
    lines = [NGINX_LINE_200, NGINX_LINE_404, NGINX_LINE_500]
    assert isinstance(detect_parser(lines), NginxParser)

def test_detect_fallback_is_ssh():
    assert isinstance(detect_parser(["totally random noise"]), SSHParser)

def test_extract_ip_ipv6():
    from log_analyzer.parsers import extract_ip
    assert extract_ip("Failed password from 2001:db8::1 port 22") == "2001:db8::1"

def test_extract_ip_prefers_ipv4():
    from log_analyzer.parsers import extract_ip
    assert extract_ip("Connection from 203.0.113.7 (2001:db8::1)") == "203.0.113.7"