from __future__ import annotations
import re
import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ParsedEvent:
    ip: str
    event_type: str   # "failed" | "accepted" | "other"
    raw: str
    extra: dict = field(default_factory=dict)


class BaseParser(ABC):

    @abstractmethod
    def parse_line(self, line: str) -> ParsedEvent | None:
        """Parse one log line. Return ParsedEvent or None if no match."""
        ...

    @classmethod
    @abstractmethod
    def detect(cls, sample: list[str]) -> bool:
        """Return True if this parser recognises the log format."""
        ...


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
)
IP_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F:\.]+\b")


def is_valid_ipv4(ip: str) -> bool:
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def extract_ip(line: str) -> str | None:
    """Extracts the first valid IPv4 or IPv6 address from a line."""
    # Find all potential chunks that look like IP addresses
    for match in IP_CANDIDATE_RE.finditer(line):
        candidate = match.group(0)
        
        # Strip trailing or leading periods/colons if caught near boundaries
        candidate = candidate.strip(":.")
        
        try:
            # Let Python's native network library validate the string
            ip = ipaddress.ip_address(candidate)
            return str(ip)
        except ValueError:
            continue
            
    return None


class SSHParser(BaseParser):

    def parse_line(self, line: str) -> ParsedEvent | None:
        ip = extract_ip(line)
        if not ip:
            return None
        s = line.lower()
        if "failed password" in s or "invalid user" in s:
            etype = "failed"
        elif "accepted password" in s:
            etype = "accepted"
        else:
            etype = "other"
        return ParsedEvent(ip=ip, event_type=etype, raw=line)

    @classmethod
    def detect(cls, sample: list[str]) -> bool:
        kw = ("failed password", "accepted password", "invalid user", "sshd")
        return any(any(k in line.lower() for k in kw) for line in sample)

  
NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[[^\]]+\] '
    r'"\S+ \S+[^"]*" (?P<status>\d{3})'
)


class NginxParser(BaseParser):

    def parse_line(self, line: str) -> ParsedEvent | None:
        m = NGINX_RE.match(line.strip())
        if not m:
            return None
        ip = m.group("ip")
        if not is_valid_ipv4(ip):
            return None
        status = int(m.group("status"))
        etype = "failed" if status >= 400 else "accepted"
        return ParsedEvent(
            ip=ip,
            event_type=etype,
            raw=line,
            extra={"status": status},
        )

    @classmethod
    def detect(cls, sample: list[str]) -> bool:
        return sum(1 for line in sample if NGINX_RE.match(line.strip())) >= 2


class ApacheParser(NginxParser):
    """Apache combined log — same format as Nginx, different detection."""

    @classmethod
    def detect(cls, sample: list[str]) -> bool:
        apache_kw = ("apache", "httpd", "mod_")
        has_kw = any(any(k in line.lower() for k in apache_kw) for line in sample)
        return has_kw and NginxParser.detect(sample)


ALL_PARSERS = [SSHParser, NginxParser, ApacheParser]


def detect_parser(lines: list[str]) -> BaseParser:
    sample = [line for line in lines[:100] if line.strip()]
    for cls in ALL_PARSERS:
        if cls.detect(sample):
            return cls()
    return SSHParser()   # safe default