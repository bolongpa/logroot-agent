"""logroot-agent: LLM agent for log anomaly detection and root-cause analysis."""

from .ingest import LogEvent, parse_line, parse_lines, parse_file, parse_timestamp
from .detect import Incident, TimeWindow, detect_incidents, signature_of
from .agent import (
    LLMClient,
    FakeLLM,
    OpenAICompatibleLLM,
    RootCauseReport,
    analyze_incident,
)
from .report import render_markdown

__all__ = [
    "LogEvent",
    "Incident",
    "TimeWindow",
    "LLMClient",
    "FakeLLM",
    "OpenAICompatibleLLM",
    "RootCauseReport",
    "analyze_incident",
    "detect_incidents",
    "signature_of",
    "parse_line",
    "parse_lines",
    "parse_file",
    "parse_timestamp",
    "render_markdown",
]

__version__ = "0.1.0"
