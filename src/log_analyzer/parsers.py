"""Log line parsers and log format auto-detection."""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import islice


@dataclass
class ParsedEvent:
    ip: str
    event_type: str  # "failed" | "accepted" | "other"
    raw: str
    extra: dict = field(default_factory=dict)
    #: When the event happened, timezone-aware; None if the line has no parseable time.
    timestamp: datetime | None = None


class BaseParser(ABC):
    #: Short name shown to the user and accepted by --log-format.
    name: str = ""

    @abstractmethod
    def parse_line(self, line: str) -> ParsedEvent | None:
        """Parse one log line. Return None if the line carries no client IP."""

    @classmethod
    @abstractmethod
    def matches(cls, line: str) -> bool:
        """Return True if the line is structurally in this parser's format."""


IP_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F:\.]+\b")


def extract_ip(line: str) -> str | None:
    """Return the first valid IPv4 or IPv6 address in the line, or None."""
    for match in IP_CANDIDATE_RE.finditer(line):
        candidate = match.group(0).strip(":.")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


# --- Timestamps -------------------------------------------------------------

_MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

# RFC 3339 prefix, as written by rsyslog's high-precision format and journalctl -o short-iso.
ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?")
# Classic BSD syslog prefix: "Feb  5 12:10:01" -- no year, no timezone.
BSD_TS_RE = re.compile(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\b")


def _parse_offset(text: str | None) -> timezone | None:
    if not text:
        return None
    if text == "Z":
        return timezone.utc
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))


def parse_syslog_time(line: str, now: datetime | None = None) -> datetime | None:
    """Return the timestamp at the start of a syslog line, or None.

    BSD syslog stamps carry no year or zone, so the year is inferred (a date
    more than a day in the future must be from last year) and the zone is
    taken to be the local zone of the machine running the analysis.
    """
    m = ISO_TS_RE.match(line)
    if m:
        ts = datetime.fromisoformat(m.group(1).replace(" ", "T"))
        tz = _parse_offset(m.group(2))
        return ts.replace(tzinfo=tz) if tz else ts.astimezone()

    m = BSD_TS_RE.match(line)
    if not m or m.group(1) not in _MONTHS:
        return None
    now = now or datetime.now()
    month, day, hh, mm, ss = _MONTHS[m.group(1)], *map(int, m.groups()[1:])
    try:
        ts = datetime(now.year, month, day, hh, mm, ss)
        if ts > now + timedelta(days=1):
            ts = ts.replace(year=now.year - 1)
    except ValueError:  # e.g. Feb 29 in a non-leap year
        return None
    return ts.astimezone()


def parse_access_time(text: str) -> datetime | None:
    """Parse an access-log time such as '01/Jan/2024:00:00:01 +0000'."""
    m = re.fullmatch(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})", text)
    if not m or m.group(2) not in _MONTHS:
        return None
    day, _, year, hh, mm, ss, offset = m.groups()
    try:
        return datetime(
            int(year),
            _MONTHS[m.group(2)],
            int(day),
            int(hh),
            int(mm),
            int(ss),
            tzinfo=_parse_offset(offset),
        )
    except ValueError:
        return None


# --- SSH (OpenSSH sshd via syslog / journald) -------------------------------

SSHD_TAG_RE = re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?:")
SSH_FAILED_RE = re.compile(r"failed (?:password|publickey)|invalid user", re.IGNORECASE)
SSH_ACCEPTED_RE = re.compile(r"accepted (?:password|publickey|keyboard-interactive)", re.IGNORECASE)


class SSHParser(BaseParser):
    name = "ssh"

    def __init__(self, now: datetime | None = None) -> None:
        # Reference point for inferring the year of BSD syslog timestamps.
        self._now = now or datetime.now()

    def parse_line(self, line: str) -> ParsedEvent | None:
        ip = extract_ip(line)
        if not ip:
            return None
        if SSH_FAILED_RE.search(line):
            etype = "failed"
        elif SSH_ACCEPTED_RE.search(line):
            etype = "accepted"
        else:
            etype = "other"
        return ParsedEvent(
            ip=ip, event_type=etype, raw=line, timestamp=parse_syslog_time(line, self._now)
        )

    @classmethod
    def matches(cls, line: str) -> bool:
        return bool(
            SSHD_TAG_RE.search(line) or SSH_FAILED_RE.search(line) or SSH_ACCEPTED_RE.search(line)
        )


# --- Web access logs (nginx and Apache share the combined log format) -------

ACCESS_RE = re.compile(
    r"^(?P<ip>[0-9A-Fa-f:.]+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"\\]*(?:\\.[^"\\]*)*)" (?P<status>\d{3})\b'
)


class AccessLogParser(BaseParser):
    """Common/combined access log, as written by both nginx and Apache httpd.

    4xx and 5xx responses count as "failed", everything else as "accepted".
    """

    name = "access"

    def parse_line(self, line: str) -> ParsedEvent | None:
        m = ACCESS_RE.match(line.strip())
        if not m:
            return None
        try:
            ip = str(ipaddress.ip_address(m.group("ip")))
        except ValueError:
            return None
        status = int(m.group("status"))
        return ParsedEvent(
            ip=ip,
            event_type="failed" if status >= 400 else "accepted",
            raw=line,
            extra={"status": status},
            timestamp=parse_access_time(m.group("time")),
        )

    @classmethod
    def matches(cls, line: str) -> bool:
        return ACCESS_RE.match(line.strip()) is not None


# --- Registry and detection --------------------------------------------------

#: Values accepted by --log-format. nginx and apache are aliases: same format.
PARSERS: dict[str, type[BaseParser]] = {
    "ssh": SSHParser,
    "access": AccessLogParser,
    "nginx": AccessLogParser,
    "apache": AccessLogParser,
}

_DETECTABLE: tuple[type[BaseParser], ...] = (SSHParser, AccessLogParser)


def detect_parser(lines: list[str], sample_size: int = 200) -> BaseParser:
    """Pick the parser whose format matches the most lines in a sample.

    Scoring every candidate, rather than taking the first one with any hit,
    keeps a single stray keyword (say, "sshd" inside a URL) from flipping a
    web log to the SSH parser. Falls back to SSH when nothing matches.
    """
    sample = list(islice((line for line in lines if line.strip()), sample_size))
    scores = {cls: sum(cls.matches(line) for line in sample) for cls in _DETECTABLE}
    best = max(_DETECTABLE, key=scores.__getitem__)  # ties go to the earlier entry
    return best() if scores[best] else SSHParser()
