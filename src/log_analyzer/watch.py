from __future__ import annotations

import time
from pathlib import Path
from typing import Callable


def tail_file(
    path: Path,
    callback: Callable[[str], None],
    poll_interval: float = 0.5,
) -> None:
    print(f"[watch] Tailing {path} — press Ctrl+C to stop")
    pos = path.stat().st_size  # start at end of file

    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                chunk = f.read()
                if chunk:
                    for line in chunk.splitlines():
                        if line.strip():
                            callback(line)
                pos = f.tell()
        except (OSError, IOError):
            pass
        time.sleep(poll_interval)