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
    assert "<svg" in html            # the chart exists at all
    assert html.count("<rect") == 2  # one bar per attacking IP