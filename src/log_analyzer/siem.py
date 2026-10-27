"""SIEM-ready JSONL output: one structured event per parsed log line."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Collection
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from log_analyzer.core import Severity, classify_severity, worst
from log_analyzer.parsers import BaseParser


@dataclass
class SIEMEvent:
    timestamp: str  # when the event happened, UTC; falls back to ingested_at if unknown
    ingested_at: str  # when log-analyzer processed the line, UTC
    source_ip: str
    event_type: str
    severity: str
    reason: str  # why severity is above INFO; empty otherwise
    log_file: str
    raw_log: str


def build_siem_events(
    lines: list[str],
    parser: BaseParser,
    log_file: str,
    fail_threshold: int,
    blocklist: Collection[str] = (),
) -> list[SIEMEvent]:
    """Convert raw log lines into structured SIEM events.

    Severity is evaluated per event, in log order, against what that IP has
    done so far -- the same way a streaming SIEM rule would see it:

    - the Nth failure from an IP is WARNING at the threshold, CRITICAL at 3x;
    - a successful login after a threshold's worth of failures is CRITICAL
      (the classic "brute force that worked" signal);
    - any event from a blocklisted IP is at least WARNING, and a successful
      login from one is CRITICAL.
    """
    ingested_at = datetime.now(timezone.utc).isoformat()
    failures: Counter[str] = Counter()
    events: list[SIEMEvent] = []

    for line in lines:
        parsed = parser.parse_line(line)
        if parsed is None:
            continue
        ip = parsed.ip
        severity = Severity.INFO
        reasons: list[str] = []

        if parsed.event_type == "failed":
            failures[ip] += 1
            severity = classify_severity(failures[ip], fail_threshold)
            if severity is not Severity.INFO:
                reasons.append(f"{failures[ip]} failures from this IP")
        elif parsed.event_type == "accepted" and failures[ip] >= fail_threshold:
            severity = Severity.CRITICAL
            reasons.append(f"successful login after {failures[ip]} failures")

        if ip in blocklist:
            login = parsed.event_type == "accepted"
            severity = worst(severity, Severity.CRITICAL if login else Severity.WARNING)
            reasons.append("successful login from blocklisted IP" if login else "blocklisted IP")

        events.append(
            SIEMEvent(
                timestamp=(
                    parsed.timestamp.astimezone(timezone.utc).isoformat()
                    if parsed.timestamp
                    else ingested_at
                ),
                ingested_at=ingested_at,
                source_ip=ip,
                event_type=parsed.event_type,
                severity=severity.value,
                reason="; ".join(reasons),
                log_file=log_file,
                raw_log=line.strip(),
            )
        )

    return events


def write_siem_jsonl(path: Path, events: list[SIEMEvent]) -> None:
    """Write one JSON object per line -- the usual JSONL format for log ingestion."""
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(asdict(event)) + "\n")
