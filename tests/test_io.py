from log_analyzer.core import analyze_lines
from log_analyzer.io import render_html_report


def test_html_report_contains_real_chart():
    lines = [
        "Failed password for root from 203.0.113.7 port 22",
        "Failed password for root from 203.0.113.7 port 22",
        "Failed password for admin from 198.51.100.4 port 22",
    ]
    report, ips, failed, accepted = analyze_lines(lines, top=5, fail_threshold=2)
    html = render_html_report("auth.log", report, ips, failed, accepted, 2)
    assert "<svg" in html  # the chart exists at all
    assert html.count("<rect") == 2  # one bar per attacking IP


def test_read_lines_replaces_undecodable_bytes(tmp_path):
    from log_analyzer.io import read_lines

    log = tmp_path / "bad.log"
    log.write_bytes(b"Invalid user \xff\xfe from 9.9.9.9 port 22\n")

    (line,) = read_lines(log)
    assert "�" in line
    assert "9.9.9.9" in line


def test_load_ip_list_ignores_comments_and_blanks(tmp_path):
    from log_analyzer.io import load_ip_list

    f = tmp_path / "ips.txt"
    f.write_text("# trusted\n10.0.0.1\n\n10.0.0.2  # office\n", encoding="utf-8")

    assert load_ip_list(f) == {"10.0.0.1", "10.0.0.2"}
