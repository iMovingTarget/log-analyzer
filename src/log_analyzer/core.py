from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from log_analyzer.parsers import BaseParser, detect_parser


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
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


def worst(*levels: Severity) -> Severity:
    """Return the most severe of the given levels (INFO if none are given)."""
    return max(levels, key=_SEVERITY_RANK.__getitem__, default=Severity.INFO)


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
    #: Blocklisted IPs seen in the log, with their event counts.
    blocklisted: list[tuple[str, int]] = field(default_factory=list)
    #: Blocklisted IPs that logged in successfully: the highest-priority finding.
    blocklisted_logins: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO


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
    """Aggregate a log into per-IP counts, threshold alerts and an overall severity.

    Allowlisted IPs are dropped entirely. Blocklisted IPs are counted like any
    other IP (a success stays a success) but are always reported, and a
    successful login from one makes the run CRITICAL.
    """
    lines = list(lines)
    total_lines = len(lines)
    if parser is None:
        parser = detect_parser(lines)

    allow_set = set(allowlist or ())
    block_set = set(blocklist or ())

    ip_counter: Counter[str] = Counter()
    failed_counter: Counter[str] = Counter()
    accepted_counter: Counter[str] = Counter()
    block_hits: Counter[str] = Counter()
    blocked_logins: set[str] = set()

    for line in lines:
        event = parser.parse_line(line)
        if event is None or event.ip in allow_set:
            continue
        ip = event.ip
        ip_counter[ip] += 1
        if event.event_type == "failed":
            failed_counter[ip] += 1
        elif event.event_type == "accepted":
            accepted_counter[ip] += 1
        if ip in block_set:
            block_hits[ip] += 1
            if event.event_type == "accepted":
                blocked_logins.add(ip)

    failed_total = sum(failed_counter.values())
    accepted_total = sum(accepted_counter.values())

    if min_events > 1:
        # Blocklisted IPs are always reported, however few events they have.
        keep = {ip for ip, total in ip_counter.items() if total >= min_events} | set(block_hits)
        ip_counter = Counter({ip: n for ip, n in ip_counter.items() if ip in keep})
        failed_counter = Counter({ip: n for ip, n in failed_counter.items() if ip in keep})
        accepted_counter = Counter({ip: n for ip, n in accepted_counter.items() if ip in keep})

    alerts = sorted(
        ((ip, n) for ip, n in failed_counter.items() if n >= fail_threshold),
        key=lambda x: x[1],
        reverse=True,
    )

    severity = worst(
        *(classify_severity(n, fail_threshold) for _, n in alerts),
        Severity.WARNING if block_hits else Severity.INFO,
        Severity.CRITICAL if blocked_logins else Severity.INFO,
    )

    report = Report(
        file=file,
        total_lines=total_lines,
        top_ips=ip_counter.most_common(top),
        failed_total=failed_total,
        accepted_total=accepted_total,
        failed_by_ip=failed_counter.most_common(top),
        alerts=alerts,
        blocklisted=block_hits.most_common(),
        blocklisted_logins=sorted(blocked_logins),
        severity=severity,
    )
    return report, ip_counter, failed_counter, accepted_counter
