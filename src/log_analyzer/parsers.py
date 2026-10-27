"""Log line parsers and log format auto-detection."""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from itertools import islice


@dataclass
class ParsedEvent:
    ip: str
    event_type: str  # "failed" | "accepted" | "other"
    raw: str
    extra: dict = field(default_factory=dict)


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


# --- SSH (OpenSSH sshd via syslog / journald) -------------------------------

SSHD_TAG_RE = re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?:")
SSH_FAILED_RE = re.compile(r"failed (?:password|publickey)|invalid user", re.IGNORECASE)
SSH_ACCEPTED_RE = re.compile(r"accepted (?:password|publickey|keyboard-interactive)", re.IGNORECASE)


class SSHParser(BaseParser):
    name = "ssh"

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
        return ParsedEvent(ip=ip, event_type=etype, raw=line)

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
