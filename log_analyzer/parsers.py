from __future__ import annotations
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
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def is_valid_ipv4(ip: str) -> bool:
    return all(0 <= int(o) <= 255 for o in ip.split("."))

def extract_ip(line: str) -> str | None:
    m = IP_RE.search(line)
    if m and is_valid_ipv4(m.group(0)):
        return m.group(0)
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
        return any(any(k in l.lower() for k in kw) for l in sample)