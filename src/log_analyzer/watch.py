"""Follow a growing log file, like `tail -F`, surviving rotation and truncation."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path


def tail_file(
    path: Path,
    callback: Callable[[str], None],
    poll_interval: float = 0.5,
    *,
    from_start: bool = False,
    should_stop: Callable[[], bool] = lambda: False,
) -> None:
    """Call callback(line) for every complete line appended to path.

    Starts at the end of the file unless from_start is True, and keeps going
    until should_stop() returns True (or forever). It handles:

    - rotation: path now refers to a different file (logrotate's default
      rename-and-create), so the new file is read from the beginning;
    - truncation: the file is shorter than the read position (copytruncate),
      so reading restarts from 0;
    - partial writes: a line is only delivered once its newline has arrived.

    The file is reopened on each poll rather than held open, so that other
    processes can rotate or delete it on Windows. The trade-off is that lines
    written to the old file between the last poll and the rotation are missed.
    """
    path = Path(path)
    st = path.stat()
    identity = (st.st_dev, st.st_ino)
    pos = 0 if from_start else st.st_size
    pending = b""

    while not should_stop():
        try:
            st = path.stat()
        except FileNotFoundError:
            # Mid-rotation: the old file was moved away, the new one isn't there yet.
            time.sleep(poll_interval)
            continue

        if (st.st_dev, st.st_ino) != identity or st.st_size < pos:
            identity, pos, pending = (st.st_dev, st.st_ino), 0, b""

        if st.st_size > pos:
            try:
                with path.open("rb") as f:
                    f.seek(pos)
                    data = f.read()
            except OSError:
                data = b""
            pos += len(data)
            *complete, pending = (pending + data).split(b"\n")
            for raw in complete:
                line = raw.decode("utf-8", errors="replace").rstrip("\r")
                if line.strip():
                    callback(line)

        time.sleep(poll_interval)
