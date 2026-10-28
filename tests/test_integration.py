from pathlib import Path

from log_analyzer.core import analyze_lines
from log_analyzer.io import read_lines
from log_analyzer.parsers import SSHParser, detect_parser

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_real_fixture_file():
    lines = read_lines(FIXTURES / "auth_sample.log")
    parser = detect_parser(lines)

    report, ip_counter, _failed_counter, _accepted_counter = analyze_lines(
        lines,
        top=5,
        fail_threshold=2,
        parser=parser,
    )

    assert isinstance(parser, SSHParser)
    assert report.total_lines == 5
    # Two failed passwords, an invalid user, and a connection closed by an authenticating user.
    assert report.failed_total == 4
    assert report.accepted_total == 1
    assert ip_counter["203.0.113.7"] == 2
    assert len(ip_counter) == 4
