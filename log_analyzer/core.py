from __future__ import annotations
from log_analyzer.parsers import BaseParser, extract_ip
from typing import Iterable
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum

class RateTracker:
    def __init__(self, window_seconds: int = 60, max_events: int = 10):
        self.window = timedelta(seconds=window_seconds)
        self.max_events = max_events
        self._events: dict[str, list[datetime]] = defaultdict(list)

    def record(self, ip: str) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - self.window
        self._events[ip] = [t for t in self._events[ip] if t > cutoff]
        self._events[ip].append(now)
        result = len(self._events[ip]) >= self.max_events
        if not self._events[ip]:  # evict empty buckets
            del self._events[ip]
        return result
    
class Severity(str, Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"

def classify_severity(failed: int, threshold: int) -> Severity:
    if failed >= threshold * 3:
        return Severity.CRITICAL
    if failed >= threshold:
        return Severity.WARNING
    return Severity.INFO

@dataclass
class Report:
    file: str
    total_lines: int
    top_ips: list[tuple[str, int]]
    failed_total: int
    accepted_total: int
    failed_by_ip: list[tuple[str, int]]
    alerts: list[tuple[str, int]]
    severity: str = "INFO" 


def analyze_lines(
    lines: Iterable[str],
    *,
    top: int,
    fail_threshold: int,
    min_events: int = 1,
    file: str = "",
    allowlist: Iterable[str] | None = None,
    blocklist: Iterable[str] | None = None,
    parser: BaseParser | None = None,
) -> tuple[Report, Counter[str], Counter[str], Counter[str]]:
    lines = list(lines)
    total_lines = len(lines)
    
    all_ips: list[str] = []
    all_failed: list[str] = []
    all_accepted: list[str] = []

    allow_set = set(allowlist) if allowlist else None
    block_set = set(blocklist) if blocklist else None

    for line in lines:
        ip = extract_ip(line)
        if not ip:
            continue

        if allow_set and ip in allow_set:
            continue  # trusted IP — skip entirely

        if block_set and ip in block_set:
            all_ips.append(ip)
            all_failed.append(ip)
            continue

        all_ips.append(ip)

        if parser is not None:
            event = parser.parse_line(line)
            if event and event.event_type == "failed":
                all_failed.append(ip)
            elif event and event.event_type == "accepted":
                all_accepted.append(ip)
        else:
            if is_failed(line):
                all_failed.append(ip)
            elif is_accepted(line):
                all_accepted.append(ip)


    # 3. Build Counters and totals once at the end
    ip_counter = Counter(all_ips)
    failed_counter = Counter(all_failed)
    accepted_counter = Counter(all_accepted)
    
    failed_total = len(all_failed)
    accepted_total = len(all_accepted)

    if min_events > 1:
        allowed = {ip for ip, total in ip_counter.items() if total >= min_events}
        ip_counter = Counter({ip: count for ip, count in ip_counter.items() if ip in allowed})
        failed_counter = Counter({ip: count for ip, count in failed_counter.items() if ip in allowed})
        accepted_counter = Counter({ip: count for ip, count in accepted_counter.items() if ip in allowed})        

    top_ips = ip_counter.most_common(top)
    failed_by_ip = failed_counter.most_common(top)

    alerts = [(ip, n) for ip, n in failed_counter.items() if n >= fail_threshold]
    alerts.sort(key=lambda x: x[1], reverse=True)

    overall = Severity.INFO
    for _, n in alerts:
        s = classify_severity(n, fail_threshold)
        if s == Severity.CRITICAL:
            overall = Severity.CRITICAL
            break
        if s == Severity.WARNING:
            overall = Severity.WARNING

    report = Report(
        file=file,
        total_lines=total_lines,
        top_ips=top_ips,
        failed_total=failed_total,
        accepted_total=accepted_total,
        failed_by_ip=failed_by_ip,
        alerts=alerts,
        severity=overall,
    )

    return report, ip_counter, failed_counter, accepted_counter


def is_failed(line: str) -> bool:
    s = line.lower()
    return "failed password" in s or "invalid user" in s


def is_accepted(line: str) -> bool:
    return "accepted password" in line.lower()