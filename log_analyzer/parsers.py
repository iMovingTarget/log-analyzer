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