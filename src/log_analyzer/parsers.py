"""Log line parsers and log format auto-detection."""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from collections import OrderedDict
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

    def reset(self) -> None:  # noqa: B027 - optional hook; stateless parsers need nothing
        """Forget state carried between lines; call before reading a log from the start."""

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

# The syslog header in front of an sshd message: optional timestamp and host, then the tag.
# Anchored at the start, so an "sshd:" inside a username can't be mistaken for it.
_SSHD_HEADER_RE = re.compile(
    r"^(?:(?:[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) \S+ )?"
    r"sshd(?:-session)?(?:\[\d+\])?: "
)

# sshd messages, matched against the whole message. The username is attacker-controlled and
# may contain spaces or text shaped like "<ip> port <n>", so it is matched greedily and the
# client address is taken from the fixed text after it, which the line must end with. Taking
# the first IP-shaped token instead would let a username such as "10.9.8.7" frame that address.
#
# Each message has a kind, which decides how it is counted (see SSHParser):
#   attempt   one failed authentication ("Failed <method> for ...")
#   accepted  a successful login
#   invalid   the client named an account that doesn't exist; not an attempt by itself
#   limit     "maximum authentication attempts exceeded"; more lines for the connection follow
#   end       the connection ended before authenticating, after a username was sent
_SSH_ADDR = r"(?P<ip>[0-9A-Fa-f:.]+)(?: port (?P<port>\d+))?"
_SSH_MESSAGES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "attempt",
        re.compile(
            rf"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) "
            rf"from {_SSH_ADDR}(?: ssh2(?:: .*)?)?$"
        ),
    ),
    (
        "accepted",
        re.compile(
            rf"^Accepted (?P<method>\S+) for (?P<user>.*) from {_SSH_ADDR}(?: ssh2(?:: .*)?)?$"
        ),
    ),
    ("invalid", re.compile(rf"^Invalid user (?P<user>.*) from {_SSH_ADDR}$")),
    # A connection that ended before authenticating, after a username was sent. On a server
    # without password logins this is often the only trace of a failed attempt: sshd logs
    # "Failed publickey" at INFO only from the MaxAuthTries/2-th failure on one connection.
    (
        "end",
        re.compile(
            r"^(?:Connection closed by|Connection reset by|Disconnected from) "
            r"(?P<who>invalid|authenticating) user (?P<user>.*) "
            r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+) \[preauth\]$"
        ),
    ),
    (
        "end",
        re.compile(
            r"^Disconnecting (?P<who>invalid|authenticating) user (?P<user>.*) "
            r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+): "
            r"Too many authentication failures(?: \[preauth\])?$"
        ),
    ),
    (
        "limit",
        re.compile(
            r"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
            r"(?P<user>.*) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+) ssh2(?: \[preauth\])?$"
        ),
    ),
)


# rsyslog's repeated-message reduction (on by default in Ubuntu) wraps a repeated message.
_REPEATED_RE = re.compile(r"^message repeated \d+ times: \[ ?(?P<message>.*)\]$")


def _sshd_message(line: str) -> str:
    """The sshd message without its syslog header (a journald MESSAGE has none)."""
    line = line.strip()
    header = _SSHD_HEADER_RE.match(line)
    message = line[header.end() :] if header else line
    repeated = _REPEATED_RE.match(message)
    return repeated.group("message") if repeated else message


def _match_ssh_message(message: str) -> tuple[str, re.Match[str]] | None:
    for kind, pattern in _SSH_MESSAGES:
        m = pattern.match(message)
        if m is None:
            continue
        try:
            ipaddress.ip_address(m.group("ip"))
        except ValueError:
            continue
        return kind, m
    return None


class SSHParser(BaseParser):
    """OpenSSH's sshd, as logged by syslog (auth.log) or journald.

    Each failed authentication counts once. sshd can log one attempt several times: an attempt
    on an unknown account logs "Invalid user", then "Failed password for invalid user" (if the
    client tried a password), then "Connection closed by invalid user ... [preauth]". So:

    - "Failed <method>" lines are failures, one per attempt;
    - the line that ends a connection before login is a failure only if no "Failed" line was
      seen for that connection (on a server without password logins it is often the only
      trace), and so is "maximum authentication attempts exceeded";
    - "Invalid user" alone is "other": a later line for the same connection counts it.

    Connections are told apart by client address and port, so the parser keeps a little state
    between lines; call reset() before parsing a log from the start again.

    Recognised messages carry ``user``, ``port``, ``method`` and ``invalid_user`` in ``extra``
    where sshd logs them. Other lines with an address are "other" events for the first
    IP-shaped token in them.
    """

    name = "ssh"

    #: Connections remembered at most; the oldest are forgotten first. A connection is
    #: forgotten when its last line is seen, so this only bounds connections whose end is
    #: missing from the log.
    max_tracked_connections = 10_000

    def __init__(self, now: datetime | None = None) -> None:
        # Reference point for inferring the year of BSD syslog timestamps.
        self._now = now or datetime.now()
        # (address, port) of connections that already produced a "failed" event.
        self._counted: OrderedDict[tuple[str, int], None] = OrderedDict()

    def reset(self) -> None:
        self._counted.clear()

    def parse_line(self, line: str) -> ParsedEvent | None:
        timestamp = parse_syslog_time(line, self._now)
        found = _match_ssh_message(_sshd_message(line))
        if found is None:
            ip = extract_ip(line)
            if not ip:
                return None
            return ParsedEvent(ip=ip, event_type="other", raw=line, timestamp=timestamp)

        kind, m = found
        fields = m.groupdict()
        ip = str(ipaddress.ip_address(fields["ip"]))
        port = int(fields["port"]) if fields.get("port") else None
        extra: dict = {"user": fields["user"]}
        if port is not None:
            extra["port"] = port
        if fields.get("method"):
            extra["method"] = fields["method"]
        if kind == "invalid" or fields.get("invalid") or fields.get("who") == "invalid":
            extra["invalid_user"] = True
        return ParsedEvent(
            ip=ip,
            event_type=self._count(kind, ip, port),
            raw=line,
            extra=extra,
            timestamp=timestamp,
        )

    def _count(self, kind: str, ip: str, port: int | None) -> str:
        """The event type for a message, given what was seen earlier on its connection."""
        if kind == "accepted":
            return "accepted"
        if kind == "invalid":
            return "other"
        if port is None:  # nothing to tell connections apart by
            return "failed"
        conn = (ip, port)
        counted = conn in self._counted
        if kind == "end":
            self._counted.pop(conn, None)
            return "other" if counted else "failed"
        if kind == "limit" and counted:
            return "other"
        self._counted[conn] = None
        self._counted.move_to_end(conn)
        while len(self._counted) > self.max_tracked_connections:
            self._counted.popitem(last=False)
        return "failed"

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
