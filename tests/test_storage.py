from log_analyzer.core import analyze_lines
from log_analyzer.storage import SQLiteStore


def test_sqlite_round_trip(tmp_path):
    report, *_ = analyze_lines(
        ["Failed password for root from 203.0.113.7 port 22"] * 3,
        top=5,
        fail_threshold=3,
        file="auth.log",
    )
    store = SQLiteStore(tmp_path / "runs.db")

    first = store.save(report)
    second = store.save(report)

    assert second == first + 1
    latest, _ = store.history(limit=2)
    assert latest["id"] == second
    assert latest["file"] == "auth.log"
    assert latest["failed"] == 3
    # tmp_path is deleted after the test; on Windows that fails if a
    # connection were left open, so this also checks connections are closed.
