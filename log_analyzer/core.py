from __future__ import annotations

import re
from typing import Iterable
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict
from datetime import datetime, timedelta, timezone

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
        return len(self._events[ip]) >= self.max_events
    
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


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
def is_valid_ipv4(ip: str) -> bool:
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def analyze_lines(
    lines: Iterable[str],
    *,
    top: int,
    fail_threshold: int,
    min_events: int = 1,
    file: str = "",
    ) -> tuple[Report, Counter[str], Counter[str], Counter[str]]:
    lines = list(lines)
    total_lines = len(lines)

    ip_counter: Counter[str] = Counter()
    failed_counter: Counter[str] = Counter()
    accepted_counter: Counter[str] = Counter()

    failed_total = 0
    accepted_total = 0

    for line in lines:
        ip = extract_ip(line)
        if not ip:
            continue

        ip_counter[ip] += 1

        if is_failed(line):
            failed_total += 1
            failed_counter[ip] += 1
        elif is_accepted(line):
            accepted_total += 1
            accepted_counter[ip] += 1

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


def extract_ip(line: str) -> str | None:
    m = IP_RE.search(line)
    if m and is_valid_ipv4(m.group(0)):
        return m.group(0)
    return None


def is_failed(line: str) -> bool:
    s = line.lower()
    return "failed password" in s or "invalid user" in s


def is_accepted(line: str) -> bool:
    return "accepted password" in line.lower()
