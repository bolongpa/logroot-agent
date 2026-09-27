"""Heuristic anomaly detection over a stream of LogEvents.

Three detectors, all cheap and deterministic (no LLM involved):

  * error bursts       - per-service error rate per time bucket vs. the other
                         buckets (leave-one-out median baseline); adjacent
                         firing buckets are merged
  * new error signatures - an error signature first seen after the warmup period
  * latency spikes     - per-bucket p95 of ``duration_ms=`` in messages vs.
                         p95 of the rest of the stream

Each detector emits :class:`Incident` objects with a severity, a time window,
and sample events. The LLM agent (see ``agent.py``) then investigates.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import timedelta

from .ingest import LogEvent

ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL"}

_DURATION_RE = re.compile(r"duration_ms=(\d+(?:\.\d+)?)")

# Normalization rules applied in order: uuids -> ips -> hex -> bare numbers.
_SIGNATURE_PATTERNS = [
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<uuid>",
    ),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<n>"),
]


def signature_of(message: str, max_len: int = 160) -> str:
    """Normalize a log message into a stable error signature.

    Numbers, UUIDs, IPs and hex tokens are replaced with placeholders so
    ``db query timeout after 30000ms job_id=job-0007`` and the same message
    with ``job-0042`` collapse to one signature.
    """
    text = message.strip().lower()
    for pattern, replacement in _SIGNATURE_PATTERNS:
        text = pattern.sub(replacement, text)
    text = re.sub(r"\s+", " ", text)
    return text[:max_len]


def duration_ms_of(event: LogEvent) -> float | None:
    """Extract ``duration_ms=<n>`` from a message, if present."""
    match = _DURATION_RE.search(event.message)
    return float(match.group(1)) if match else None


@dataclass
class TimeWindow:
    start: object  # datetime
    end: object  # datetime

    def iso(self) -> str:
        return f"{self.start.isoformat()}..{self.end.isoformat()}"


@dataclass
class Incident:
    id: str
    kind: str  # "error_burst" | "new_error_signature" | "latency_spike"
    service: str
    signature: str
    severity: str  # "low" | "medium" | "high"
    window: TimeWindow
    description: str
    sample_events: list = field(default_factory=list)
    count: int = 0


def _incident_id(kind: str, service: str, window: TimeWindow, signature: str) -> str:
    digest = hashlib.sha1(f"{kind}|{service}|{signature}".encode()).hexdigest()[:6]
    stamp = window.start.strftime("%Y%m%dT%H%M%S")
    return f"{kind}-{service}-{stamp}-{digest}"


def _is_error(event: LogEvent) -> bool:
    return event.level in ERROR_LEVELS


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    idx = max(0, math.ceil(pct / 100 * len(ordered)) - 1)
    return ordered[idx]


def _bucketize(events: list[LogEvent], window_seconds: float):
    """Split the stream into consecutive non-overlapping windows."""
    t_start = events[0].timestamp
    span = (events[-1].timestamp - t_start).total_seconds()
    n = max(1, math.ceil(span / window_seconds))
    buckets: list[list[LogEvent]] = [[] for _ in range(n)]

    def bounds(i: int) -> TimeWindow:
        return TimeWindow(
            start=t_start + timedelta(seconds=i * window_seconds),
            end=t_start + timedelta(seconds=(i + 1) * window_seconds),
        )

    for event in events:
        idx = min(n - 1, int((event.timestamp - t_start).total_seconds() // window_seconds))
        buckets[idx].append(event)
    return buckets, bounds


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2 if ordered else 0.0


def _merge_runs(indices: list[int]) -> list[list[int]]:
    """Merge consecutive bucket indices into runs, e.g. [1,2,4] -> [[1,2],[4]]."""
    runs: list[list[int]] = []
    for idx in sorted(indices):
        if runs and idx == runs[-1][-1] + 1:
            runs[-1].append(idx)
        else:
            runs.append([idx])
    return runs


def _error_bursts(buckets, bounds, *, burst_min_count, burst_factor):
    services = {e.service for b in buckets for e in b}
    incidents = []
    for service in sorted(services):
        counts = [
            sum(1 for e in bucket if e.service == service and _is_error(e))
            for bucket in buckets
        ]
        firing = []
        for i, count in enumerate(counts):
            if count < burst_min_count:
                continue
            baseline = _median(counts[:i] + counts[i + 1 :])  # leave-one-out
            if count >= max(1.0, baseline) * burst_factor:
                firing.append(i)
        for run in _merge_runs(firing):
            run_events = [
                e for i in run for e in buckets[i]
                if e.service == service and _is_error(e)
            ]
            window = TimeWindow(start=bounds(run[0]).start, end=bounds(run[-1]).end)
            count = len(run_events)
            sig_counts: dict[str, int] = {}
            for event in run_events:
                sig = signature_of(event.message)
                sig_counts[sig] = sig_counts.get(sig, 0) + 1
            top_sig = max(sig_counts, key=sig_counts.get)
            if count >= 20 or any(e.level in {"CRITICAL", "FATAL"} for e in run_events):
                severity = "high"
            elif count >= 8:
                severity = "medium"
            else:
                severity = "low"
            incidents.append(
                Incident(
                    id=_incident_id("error_burst", service, window, top_sig),
                    kind="error_burst",
                    service=service,
                    signature=top_sig,
                    severity=severity,
                    window=window,
                    description=(
                        f"{count} errors in a {len(run) * int((bounds(1).end - bounds(1).start).total_seconds()) // 60}-min "
                        f"sliding window (typical ~{_median(counts):.1f} per window)"
                    ),
                    sample_events=run_events[:5],
                    count=count,
                )
            )
    return incidents


def _new_error_signatures(buckets, bounds, t_start, span_seconds, *, new_signature_min_count, warmup_fraction):
    warmup_end = t_start + timedelta(seconds=span_seconds * warmup_fraction)
    first_seen: dict[tuple[str, str], LogEvent] = {}
    groups: dict[tuple[str, str], list[LogEvent]] = {}
    for bucket in buckets:
        for event in bucket:
            if not _is_error(event):
                continue
            key = (event.service, signature_of(event.message))
            groups.setdefault(key, []).append(event)
            if key not in first_seen:
                first_seen[key] = event

    incidents = []
    for key, events in groups.items():
        first = first_seen[key]
        if first.timestamp < warmup_end or len(events) < new_signature_min_count:
            continue
        service, sig = key
        idx = next(
            i for i, bucket in enumerate(buckets) if first in bucket
        )
        window = bounds(idx)
        severity = "medium" if len(events) >= 5 else "low"
        incidents.append(
            Incident(
                id=_incident_id("new_error_signature", service, window, sig),
                kind="new_error_signature",
                service=service,
                signature=sig,
                severity=severity,
                window=window,
                description=(
                    f"Brand-new error signature first seen at {first.timestamp.isoformat()}, "
                    f"occurred {len(events)}x total"
                ),
                sample_events=events[:5],
                count=len(events),
            )
        )
    return incidents


def _latency_spikes(buckets, bounds, *, latency_factor, latency_min_ms):
    def bucket_p95(bucket, service):
        durs = [
            d for e in bucket
            if e.service == service and (d := duration_ms_of(e)) is not None
        ]
        return _percentile(durs, 95) if durs else None

    services = {e.service for b in buckets for e in b}
    incidents = []
    for service in sorted(services):
        p95s = [bucket_p95(bucket, service) for bucket in buckets]
        firing = []
        for i, p in enumerate(p95s):
            if p is None or p < latency_min_ms:
                continue
            # Baseline: durations from strictly earlier buckets (causal: what
            # "normal" looked like before this bucket). Falls back to the rest
            # of the stream when there is not enough past data.
            past_durs = [
                d for j, bucket in enumerate(buckets) if j < i for e in bucket
                if e.service == service and (d := duration_ms_of(e)) is not None
            ]
            if len(past_durs) < 5:
                past_durs = [
                    d for j, bucket in enumerate(buckets) if j != i for e in bucket
                    if e.service == service and (d := duration_ms_of(e)) is not None
                ]
            hist_p95 = _percentile(past_durs, 95) if past_durs else 0.0
            if p >= max(latency_min_ms, hist_p95 * latency_factor):
                firing.append(i)
        for run in _merge_runs(firing):
            peak = max(p95s[i] for i in run if p95s[i] is not None)
            window = TimeWindow(start=bounds(run[0]).start, end=bounds(run[-1]).end)
            severity = "high" if peak >= 8000 else "medium"
            sig = f"p95 latency {peak:.0f}ms"
            sample = [
                e for i in run for e in buckets[i]
                if e.service == service and (duration_ms_of(e) or 0) >= peak * 0.5
            ][:5]
            incidents.append(
                Incident(
                    id=_incident_id("latency_spike", service, window, sig),
                    kind="latency_spike",
                    service=service,
                    signature=sig,
                    severity=severity,
                    window=window,
                    description=f"p95 latency {peak:.0f}ms in window (vs typical history)",
                    sample_events=sample,
                    count=sum(
                        1 for i in run for e in buckets[i]
                        if e.service == service and duration_ms_of(e) is not None
                    ),
                )
            )
    return incidents


def detect_incidents(
    events: list[LogEvent],
    *,
    window_seconds: float = 300,
    burst_min_count: int = 5,
    burst_factor: float = 4.0,
    latency_factor: float = 3.0,
    latency_min_ms: float = 1000.0,
    new_signature_min_count: int = 2,
    warmup_fraction: float = 0.25,
) -> list[Incident]:
    """Run all heuristic detectors over ``events``.

    The stream is split into consecutive ``window_seconds`` buckets; each
    bucket is compared against the rest of the stream (leave-one-out
    baseline), so bursts are found wherever they occur -- not just at the
    tail. New error signatures are those first seen after the warmup period.
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    if not ordered:
        return []
    buckets, bounds = _bucketize(ordered, window_seconds)
    t_start = ordered[0].timestamp
    span_seconds = (ordered[-1].timestamp - t_start).total_seconds()

    incidents: list[Incident] = []
    incidents.extend(
        _error_bursts(buckets, bounds, burst_min_count=burst_min_count, burst_factor=burst_factor)
    )
    incidents.extend(
        _new_error_signatures(
            buckets, bounds, t_start, span_seconds,
            new_signature_min_count=new_signature_min_count,
            warmup_fraction=warmup_fraction,
        )
    )
    incidents.extend(
        _latency_spikes(buckets, bounds, latency_factor=latency_factor, latency_min_ms=latency_min_ms)
    )
    rank = {"high": 0, "medium": 1, "low": 2}
    incidents.sort(key=lambda i: (rank.get(i.severity, 3), i.window.start, i.service))
    return incidents
