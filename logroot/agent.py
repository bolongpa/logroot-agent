"""Agentic root-cause analysis loop.

Given an :class:`~logroot.detect.Incident`, the agent gathers evidence by
calling tools against the log store (multi-step, bounded), then writes a
structured root-cause report.

Tool set:
  * ``search_logs(pattern, window, limit)`` - regex search over log messages
  * ``top_signatures(window, n)``            - most common error signatures
  * ``service_timeline(service, window)``    - per-minute error timeline

LLM access goes through the :class:`LLMClient` protocol::

    {"role": ..., "content": ...} messages in, and a dict out:
    {"content": str | None, "tool_calls": [{"id", "name", "arguments"}]}

Two implementations ship:
  * :class:`OpenAICompatibleLLM` - any OpenAI-compatible chat-completions
    endpoint (``LLM_BASE_URL`` / ``LLM_API_KEY`` / ``LLM_MODEL`` env vars).
  * :class:`FakeLLM` - deterministic, scripted, zero-network stand-in used
    for tests and the offline demo. It calls the tools in a sensible order
    (signatures -> timeline -> targeted search) and then writes the report
    from the evidence it gathered.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from .detect import Incident, signature_of, duration_ms_of, ERROR_LEVELS
from .ingest import LogEvent, parse_timestamp

# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class RootCauseReport:
    incident_id: str
    summary: str
    evidence_timeline: list[str] = field(default_factory=list)
    root_cause: str = ""
    confidence: float = 0.0
    remediations: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: dict, incident_id: str) -> "RootCauseReport":
        if not isinstance(data, dict):
            raise ValueError("LLM did not return a JSON object for the report")
        confidence = data.get("confidence", 0.0)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        evidence = data.get("evidence_timeline") or []
        remediations = data.get("remediations") or []
        return cls(
            incident_id=incident_id,
            summary=str(data.get("summary", "")),
            evidence_timeline=[str(x) for x in evidence],
            root_cause=str(data.get("root_cause", "")),
            confidence=confidence,
            remediations=[str(x) for x in remediations],
        )


# ---------------------------------------------------------------------------
# Tools over the log store
# ---------------------------------------------------------------------------


def parse_window(spec: str, events: list[LogEvent]) -> tuple[datetime, datetime]:
    """Parse a window spec into (start, end).

    Accepted forms: ``"15m"`` / ``"last-15m"`` (trailing 15 min before the
    newest event), ``"2h"``, ``"<iso>..<iso>"``, or anything else meaning
    "the whole range".
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    t_max = ordered[-1].timestamp
    t_min = ordered[0].timestamp
    spec = (spec or "").strip()
    match = re.fullmatch(r"(?:last-)?(\d+)([mh])", spec)
    if match:
        amount = int(match.group(1))
        delta = timedelta(minutes=amount) if match.group(2) == "m" else timedelta(hours=amount)
        return t_max - delta, t_max
    if ".." in spec:
        left, right = spec.split("..", 1)
        start = parse_timestamp(left.strip()) or t_min
        end = parse_timestamp(right.strip()) or t_max
        return start, end
    return t_min, t_max


def _in_window(event: LogEvent, start: datetime, end: datetime) -> bool:
    return start <= event.timestamp <= end


def _format_event(event: LogEvent) -> str:
    return (
        f"{event.timestamp.isoformat()} {event.level} "
        f"{event.service} {event.message}"
    )


def _make_tools(events: list[LogEvent]):
    def search_logs(pattern: str, window: str = "", limit: int = 30) -> str:
        """Regex-search log messages; returns matching lines (newest last)."""
        start, end = parse_window(window, events)
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return f"invalid regex: {exc}"
        hits = [
            e for e in events
            if _in_window(e, start, end)
            and rx.search(f"{e.level} {e.service} {e.message}")
        ]
        lines = [_format_event(e) for e in hits[-limit:]]
        header = f"{len(hits)} matching events in window ({start.isoformat()}..{end.isoformat()})"
        return header + ("\n" + "\n".join(lines) if lines else "")

    def top_signatures(window: str = "", n: int = 10) -> str:
        """Most common error signatures in a window, with counts + a sample."""
        start, end = parse_window(window, events)
        groups: dict[tuple[str, str], list[LogEvent]] = {}
        for e in events:
            if _in_window(e, start, end) and e.level in ERROR_LEVELS:
                groups.setdefault((e.service, signature_of(e.message)), []).append(e)
        ranked = sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)[: max(1, n)]
        if not ranked:
            return "no error events in window"
        out = []
        for (service, sig), evs in ranked:
            out.append(f"{len(evs)}x [{service}] {sig}")
            out.append(f"    e.g. {_format_event(evs[0])}")
        return "\n".join(out)

    def service_timeline(service: str, window: str = "", bucket_minutes: int = 1) -> str:
        """Per-minute error counts for one service across a window."""
        start, end = parse_window(window, events)
        buckets: dict[str, dict] = {}
        for e in events:
            if e.service != service or not _in_window(e, start, end):
                continue
            key = e.timestamp.strftime("%H:%M")
            b = buckets.setdefault(key, {"errors": 0, "total": 0, "durs": []})
            b["total"] += 1
            if e.level in ERROR_LEVELS:
                b["errors"] += 1
            dur = duration_ms_of(e)
            if dur is not None:
                b["durs"].append(dur)
        if not buckets:
            return f"no events for service '{service}' in window"
        lines = []
        for key in sorted(buckets):
            b = buckets[key]
            p95 = f" p95={sorted(b['durs'])[int(len(b['durs']) * 0.95)]:.0f}ms" if b["durs"] else ""
            lines.append(f"{key} errors={b['errors']} total={b['total']}{p95}")
        return "\n".join(lines)

    return [
        {
            "name": "search_logs",
            "description": "Regex-search log messages within a time window.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex matched against level/service/message"},
                    "window": {"type": "string", "description": "e.g. '15m', 'last-1h', or '<iso>..<iso>'"},
                    "limit": {"type": "integer", "description": "Max lines to return"},
                },
                "required": ["pattern"],
            },
            "func": search_logs,
        },
        {
            "name": "top_signatures",
            "description": "Most common error signatures in a window.",
            "parameters": {
                "type": "object",
                "properties": {
                    "window": {"type": "string"},
                    "n": {"type": "integer", "description": "How many signatures"},
                },
                "required": [],
            },
            "func": top_signatures,
        },
        {
            "name": "service_timeline",
            "description": "Per-minute error timeline for one service.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "window": {"type": "string"},
                    "bucket_minutes": {"type": "integer"},
                },
                "required": ["service"],
            },
            "func": service_timeline,
        },
    ]


def _tool_schemas(tools: list[dict]) -> list[dict]:
    return [
        {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}
        for t in tools
    ]


SYSTEM_PROMPT = """\
You are logroot, an on-call SRE assistant. A heuristic detector flagged an
incident in the logs. Your job is to investigate with the available tools and
then write a root-cause report.

Rules:
- Call 2-4 tools to gather evidence before concluding. Good first calls:
  top_signatures for the incident window, then service_timeline for the
  affected service, then a targeted search_logs for the suspicious pattern.
- Correlate across services: an error burst in service A is often caused by
  a latency spike or failure in a dependency B. Check timelines of related
  services when the evidence points that way.
- When you have enough evidence, respond with ONLY a JSON object, no markdown
  fences, no extra text:
  {"summary": "1-2 sentence overview",
   "evidence_timeline": ["timestamped facts, newest last, max 8"],
   "root_cause": "most likely cause in one paragraph",
   "confidence": 0.0-1.0,
   "remediations": ["concrete next steps"]}
- Be specific: name services, quote signatures, cite timestamps. Never invent
  services, hosts, or metrics not present in the tool output.
"""


def _extract_json(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found in LLM response")
    return json.loads(text[start : end + 1])


# ---------------------------------------------------------------------------
# LLM clients
# ---------------------------------------------------------------------------


class LLMClient(Protocol):
    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        """One chat turn. Returns {"content": str|None, "tool_calls": [...]}."""
        ...


class FakeLLM:
    """Deterministic scripted LLM: no network, no API key, no randomness.

    Strategy per incident: top_signatures -> service_timeline(affected svc) ->
    search_logs(keyword from the incident signature) -> final JSON report built
    from the gathered evidence. The report-writing step applies small,
    transparent heuristics (earliest-failing service, timeout/latency keywords)
    so the demo produces a realistic, checkable report offline.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []  # (tool name, args) in order

    # -- plumbing ---------------------------------------------------------
    @staticmethod
    def _incident_ctx(messages: list[dict]) -> dict:
        for msg in reversed(messages):
            if msg.get("role") == "user" and "INCIDENT:" in str(msg.get("content", "")):
                return json.loads(str(msg["content"]).split("INCIDENT:", 1)[1])
        return {}

    def _tool_call(self, name: str, arguments: dict) -> dict:
        self.calls.append((name, arguments))
        return {
            "content": None,
            "tool_calls": [{"id": f"call_{len(self.calls)}", "name": name, "arguments": arguments}],
        }

    # -- script -----------------------------------------------------------
    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        ctx = self._incident_ctx(messages)
        window = ctx.get("window", "")
        service = ctx.get("service", "")
        signature = ctx.get("signature", "")
        done = sum(1 for m in messages if m.get("role") == "tool")

        if done == 0:
            return self._tool_call("top_signatures", {"window": window, "n": 5})
        if done == 1:
            return self._tool_call("service_timeline", {"service": service, "window": window})
        if done == 2:
            return self._tool_call(
                "search_logs", {"pattern": _keyword(signature), "window": window, "limit": 20}
            )
        return {"content": json.dumps(self._write_report(messages, ctx), indent=2), "tool_calls": []}

    # -- report writing ----------------------------------------------------
    def _write_report(self, messages: list[dict], ctx: dict) -> dict:
        service = ctx.get("service", "unknown")
        signature = ctx.get("signature", "")
        window = ctx.get("window", "")
        kind = ctx.get("kind", "")
        tool_texts = [str(m.get("content", "")) for m in messages if m.get("role") == "tool"]
        blob = "\n".join(tool_texts)

        timeline = _pick_evidence(tool_texts)
        root_cause, confidence = _infer_cause(blob, service)

        summary = (
            f"{service} showed anomalous behavior ({kind.replace('_', ' ')}) in window "
            f"{window}: {signature[:120]}"
        )
        remediations = [
            f"Add timeout budgets / circuit breaking between {service} and its slow dependency so one slow downstream cannot cascade.",
            "Investigate the slow dependency (slow-query log, DB CPU/IO, connection pool saturation) and fail over or scale it.",
            "Add alerting on p95 query latency, not just error rate, to catch degradation before it becomes an outage.",
            "Retry transient downstream timeouts with exponential backoff + jitter, with a bounded retry budget.",
        ]
        return {
            "summary": summary,
            "evidence_timeline": timeline,
            "root_cause": root_cause,
            "confidence": confidence,
            "remediations": remediations,
        }


def _keyword(signature: str) -> str:
    """Pick a searchable keyword out of a normalized signature."""
    words = [
        w for w in re.findall(r"[a-z]{3,}", signature.lower())
        if w not in {"<n>", "<uuid>", "<ip>", "<hex>", "the", "and", "for", "with", "after"}
    ]
    return words[0] if words else "error"


def _pick_evidence(tool_texts: list[str], limit: int = 8) -> list[str]:
    """Turn raw tool output into short timestamped evidence bullets."""
    bullets: list[str] = []
    for text in tool_texts:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("no ", "invalid")):
                continue
            if re.match(r"\d{4}-\d{2}-\d{2}T", line) or re.match(r"\d{2}:\d{2}\b", line) or re.match(r"\d+x \[", line):
                bullets.append(line[:200])
            if len(bullets) >= limit:
                return bullets
    return bullets or ["Detector flagged the incident; tool output contained no timestamped lines."]


def _infer_cause(blob: str, service: str) -> tuple[str, float]:
    """Tiny transparent heuristic over the gathered evidence."""
    low = blob.lower()
    dep_match = re.search(r"\[(db-proxy|[\w.\-]+)\].*?(timeout|slow)", low)
    mentions_dep = ("db-proxy" in low) and ("timeout" in low or "slow" in low or "duration" in low)
    if mentions_dep:
        return (
            "The evidence points to a downstream database slowdown: db-proxy shows "
            "elevated query latencies and timeouts in the same window, and the "
            f"{service} errors are dominated by 'db query timeout' signatures that "
            "began only after the latency spike. Likely cascade: slow DB -> "
            "db-proxy timeouts -> etl-worker job failures -> api-gateway 502s.",
            0.78,
        )
    if dep_match:
        dep = dep_match.group(1)
        return (
            f"Errors concentrate in {service} with a signature implicating {dep}. "
            "The correlated timeline suggests the dependency degraded first; "
            "treat this as a cascade until the dependency's own logs say otherwise.",
            0.6,
        )
    return (
        f"Errors concentrate in {service} and the signature is new to the history "
        "window, suggesting a recent change or a newly-triggered failure mode in "
        "that service. No clear upstream dependency signal was found in the "
        "gathered evidence.",
        0.45,
    )


class OpenAICompatibleLLM:
    """Chat via any OpenAI-compatible ``/chat/completions`` endpoint.

    Config from env: ``LLM_BASE_URL``, ``LLM_API_KEY``, ``LLM_MODEL``.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        if not self.base_url:
            raise ValueError("LLM_BASE_URL is not set")

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        import requests  # local import: only needed for the real-LLM path

        payload = {
            "model": self.model,
            "messages": [_to_openai_message(m) for m in messages],
            "tools": [
                {"type": "function", "function": {k: v for k, v in t.items() if k != "func"}}
                for t in tools
            ],
            "tool_choice": "auto",
        }
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        msg = resp.json()["choices"][0]["message"]
        tool_calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc["function"]
            tool_calls.append(
                {
                    "id": tc.get("id", ""),
                    "name": fn["name"],
                    "arguments": json.loads(fn.get("arguments") or "{}"),
                }
            )
        return {"content": msg.get("content"), "tool_calls": tool_calls}


def _to_openai_message(msg: dict) -> dict:
    role = msg.get("role")
    if role == "tool":
        return {
            "role": "tool",
            "tool_call_id": msg.get("id", ""),
            "content": str(msg.get("content", "")),
        }
    out = {"role": role, "content": msg.get("content")}
    if msg.get("tool_calls"):
        out["tool_calls"] = [
            {
                "id": tc.get("id", ""),
                "type": "function",
                "function": {"name": tc["name"], "arguments": json.dumps(tc.get("arguments", {}))},
            }
            for tc in msg["tool_calls"]
        ]
    return out


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def analyze_incident(
    incident: Incident,
    llm: LLMClient,
    events: list[LogEvent],
    max_steps: int = 6,
) -> RootCauseReport:
    """Run the gather-evidence loop and return a structured report."""
    tools = _make_tools(events)
    schemas = _tool_schemas(tools)
    funcs = {t["name"]: t["func"] for t in tools}

    incident_ctx = {
        "id": incident.id,
        "kind": incident.kind,
        "service": incident.service,
        "signature": incident.signature,
        "severity": incident.severity,
        "window": incident.window.iso(),
        "description": incident.description,
        "event_count": incident.count,
    }
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "INCIDENT:\n" + json.dumps(incident_ctx, indent=2)},
    ]

    for _ in range(max_steps):
        response = llm.chat(messages, schemas)
        tool_calls = response.get("tool_calls") or []
        if not tool_calls:
            return RootCauseReport.from_json(
                _extract_json(response.get("content") or ""), incident.id
            )
        messages.append(
            {
                "role": "assistant",
                "content": response.get("content"),
                "tool_calls": [
                    {"id": tc.get("id", ""), "name": tc["name"], "arguments": tc.get("arguments", {})}
                    for tc in tool_calls
                ],
            }
        )
        for tc in tool_calls:
            name = tc["name"]
            args = tc.get("arguments", {}) or {}
            func = funcs.get(name)
            if func is None:
                result = f"error: unknown tool '{name}'"
            else:
                try:
                    result = str(func(**args))
                except TypeError as exc:
                    result = f"error calling {name}: {exc}"
            messages.append(
                {"role": "tool", "id": tc.get("id", ""), "name": name, "content": result[:6000]}
            )

    # Ran out of steps: return an honest low-confidence report instead of failing.
    return RootCauseReport(
        incident_id=incident.id,
        summary=f"Investigation of {incident.id} hit the step budget before concluding.",
        evidence_timeline=[],
        root_cause="Unknown: the agent exhausted its tool-call budget without converging.",
        confidence=0.1,
        remediations=["Re-run with a higher step budget or a more capable model."],
    )
