from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from log_analyzer.core import Severity, classify_severity
from log_analyzer.parsers import BaseParser


@dataclass
class SIEMEvent:
    timestamp: str
    source_ip: str
    event_type: str
    severity: str
    log_file: str
    raw_log: str


def build_siem_events(
    lines: list[str],
    parser: BaseParser,
    log_file: str,
    fail_threshold: int,
) -> list[SIEMEvent]:
    """Convert raw log lines into structured SIEM events using the given parser."""
    events: list[SIEMEvent] = []
    ingest_time = datetime.now(timezone.utc).isoformat()

    for line in lines:
        parsed = parser.parse_line(line)
        if parsed is None:
            continue

        if parsed.event_type == "failed":
            severity = classify_severity(1, fail_threshold)
        else:
            severity = Severity.INFO

        events.append(
            SIEMEvent(
                timestamp=ingest_time,
                source_ip=parsed.ip,
                event_type=parsed.event_type,
                severity=severity.value if hasattr(severity, "value") else str(severity),
                log_file=log_file,
                raw_log=line.strip(),
            )
        )

    return events


def write_siem_jsonl(path: Path, events: list[SIEMEvent]) -> None:
    """Write one JSON object per line — standard JSONL format for log ingestion."""
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(asdict(event)) + "\n")
