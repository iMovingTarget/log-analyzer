import os
import threading
import time
from contextlib import contextmanager

from log_analyzer.watch import tail_file


def _wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@contextmanager
def tailing(path):
    seen: list[str] = []
    stop = threading.Event()
    worker = threading.Thread(
        target=tail_file,
        args=(path, seen.append),
        kwargs={"poll_interval": 0.01, "should_stop": stop.is_set},
        daemon=True,
    )
    worker.start()
    time.sleep(0.2)  # let the tailer take its starting position
    try:
        yield seen
    finally:
        stop.set()
        worker.join(timeout=2)


def _append(path, text):
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(text)


def test_reads_only_lines_appended_after_start(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old line\n", encoding="utf-8")

    with tailing(log) as seen:
        _append(log, "new 1\nnew 2\n")
        assert _wait_for(lambda: seen == ["new 1", "new 2"]), seen


def test_partial_line_waits_for_its_newline(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")

    with tailing(log) as seen:
        _append(log, "half a li")
        time.sleep(0.1)
        assert seen == []
        _append(log, "ne\r\n")
        assert _wait_for(lambda: seen == ["half a line"]), seen


def test_survives_truncation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("x" * 100 + "\n", encoding="utf-8")

    with tailing(log) as seen:
        log.write_text("after truncate\n", encoding="utf-8")  # copytruncate-style
        assert _wait_for(lambda: "after truncate" in seen), seen


def test_survives_rotation(tmp_path):
    # Regression: after logrotate moved the file away, the old read position
    # was applied to the new file and nothing was ever read again.
    log = tmp_path / "auth.log"
    log.write_text("x" * 100 + "\n", encoding="utf-8")

    with tailing(log) as seen:
        for _ in range(50):  # Windows refuses the rename while the tailer has it open
            try:
                os.replace(log, tmp_path / "auth.log.1")
                break
            except PermissionError:
                time.sleep(0.01)
        log.write_text("after rotate\n", encoding="utf-8")
        assert _wait_for(lambda: "after rotate" in seen), seen
