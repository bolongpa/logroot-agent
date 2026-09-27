"""Log ingestion: parse common log formats into normalized LogEvent records.

Supported formats:
  * syslog-ish:  ``2026-09-26T21:00:01Z ERROR etl-worker db query timeout``
  * JSON-lines: ``{"timestamp": "...", "level": "ERROR", "service": "etl-worker", "msg": "..."}``
    (also accepts ``time``/``@timestamp``/``ts``, ``severity``, ``app``/``logger``,
    and ``message`` as key aliases)

Parsing is deliberately tolerant: blank lines and malformed lines return
``None`` / are skipped instead of raising, so a messy real-world log file
never crashes the pipeline.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

#: Log levels we recognise (case-insensitive on input, stored upper-case).
LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"}

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<level>[A-Za-z]+)\s+(?P<service>[\w.\-]+)\s+(?P<msg>.*)$"
)


@dataclass
class LogEvent:
    """A single normalized log event."""

    timestamp: datetime
    level: str
    service: str
    message: str
    raw: str = ""
    fields: dict = field(default_factory=dict)


def parse_timestamp(value: object) -> Optional[datetime]:
    """Best-effort timestamp parsing. Returns None when unparseable."""
    if value is None:
        return None
    if isinstance(value, bool):  # guard: bool is a subclass of int
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_json_object(obj: dict, raw: str) -> Optional[LogEvent]:
    ts = parse_timestamp(
        obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or obj.get("ts")
    )
    if ts is None:
        return None
    level = str(obj.get("level") or obj.get("severity") or "INFO").upper()
    service = str(obj.get("service") or obj.get("app") or obj.get("logger") or "unknown")
    message = str(obj.get("msg") if obj.get("msg") is not None else obj.get("message", ""))
    return LogEvent(timestamp=ts, level=level, service=service, message=message, raw=raw, fields=obj)


def _parse_syslog_line(line: str) -> Optional[LogEvent]:
    match = _SYSLOG_RE.match(line)
    if not match:
        return None
    ts = parse_timestamp(match.group("ts"))
    level = match.group("level").upper()
    if ts is None or level not in LEVELS:
        return None
    return LogEvent(
        timestamp=ts,
        level=level,
        service=match.group("service"),
        message=match.group("msg"),
        raw=line,
    )


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse one log line. Returns None for blank/malformed lines (never raises)."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(obj, dict):
                event = _parse_json_object(obj, line)
                if event is not None:
                    return event
                # Valid JSON but not a log record -> fall through to syslog attempt.
    return _parse_syslog_line(line)


def parse_lines(lines: Iterable[str]) -> list[LogEvent]:
    """Parse an iterable of lines, skipping anything malformed."""
    return [event for line in lines if (event := parse_line(line)) is not None]


def parse_file(path: str, encoding: str = "utf-8") -> list[LogEvent]:
    """Parse a log file, tolerating undecodable bytes."""
    with open(path, "r", encoding=encoding, errors="replace") as fh:
        return parse_lines(fh)
