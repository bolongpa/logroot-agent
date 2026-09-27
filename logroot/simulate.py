"""Synthetic log generator: a fake microservice landscape for demos and tests.

Services:
  * ``api-gateway`` - HTTP ingress, logs request lines with ``duration_ms=``
  * ``etl-worker``  - batch ETL jobs, logs per-job progress with ``duration_ms=``
  * ``db-proxy``    - database proxy, logs query latencies with ``duration_ms=``

Incident injection (``incident="db-slowdown"``): the downstream database gets
slow at ``incident_at_min`` for ``incident_len_min`` minutes. ``db-proxy``
logs slow queries and timeouts, ``etl-worker`` jobs start failing with
``db query timeout`` errors (an error burst), and ``api-gateway`` sees a few
upstream 502s. This mirrors a classic cascading-failure on-call scenario.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .ingest import LogEvent

SERVICES = ["api-gateway", "etl-worker", "db-proxy"]


def _ts(base: datetime, minute: int, second: int) -> datetime:
    return base + timedelta(minutes=minute, seconds=second)


def generate_logs(
    duration_min: int = 30,
    incident: str | None = "db-slowdown",
    incident_at_min: int = 20,
    incident_len_min: int = 8,
    seed: int = 42,
) -> list[LogEvent]:
    """Generate a deterministic stream of synthetic log events."""
    rng = random.Random(seed)
    base = datetime(2026, 9, 26, 21, 0, 0, tzinfo=timezone.utc)
    events: list[LogEvent] = []

    def in_incident(minute: int) -> bool:
        return (
            incident == "db-slowdown"
            and incident_at_min <= minute < incident_at_min + incident_len_min
        )

    for minute in range(duration_min):
        bad = in_incident(minute)

        # --- api-gateway: steady HTTP traffic ---------------------------------
        for _ in range(rng.randint(3, 6)):
            dur = rng.randint(20, 180)
            req = rng.randint(1000, 9999)
            if bad and rng.random() < 0.25:
                events.append(
                    LogEvent(
                        _ts(base, minute, rng.randint(0, 59)),
                        "ERROR",
                        "api-gateway",
                        f"POST /v1/extract 502 duration_ms={rng.randint(29000, 32000)} "
                        f"req_id={req} upstream=etl-worker",
                    )
                )
            else:
                events.append(
                    LogEvent(
                        _ts(base, minute, rng.randint(0, 59)),
                        "INFO",
                        "api-gateway",
                        f"GET /v1/extract 200 duration_ms={dur} req_id={req}",
                    )
                )

        # --- db-proxy: query latencies ----------------------------------------
        for _ in range(rng.randint(3, 5)):
            if bad:
                dur = rng.randint(6000, 15000)
                level = "ERROR" if rng.random() < 0.3 else "WARN"
                msg = (
                    f"query timeout after 30000ms table=events duration_ms={dur}"
                    if level == "ERROR"
                    else f"slow query table=events duration_ms={dur}"
                )
            else:
                dur = rng.randint(20, 140)
                level = "INFO"
                msg = f"query OK table=events duration_ms={dur}"
            events.append(
                LogEvent(_ts(base, minute, rng.randint(0, 59)), level, "db-proxy", msg)
            )

        # --- etl-worker: batch jobs -------------------------------------------
        for _ in range(rng.randint(2, 4)):
            job = f"job-{rng.randint(1, 20):04d}"
            if bad and rng.random() < 0.8:
                events.append(
                    LogEvent(
                        _ts(base, minute, rng.randint(0, 59)),
                        "ERROR",
                        "etl-worker",
                        f"db query timeout after 30000ms job_id={job} stage=load "
                        f"duration_ms={rng.randint(30000, 31000)}",
                    )
                )
            else:
                events.append(
                    LogEvent(
                        _ts(base, minute, rng.randint(0, 59)),
                        "INFO",
                        "etl-worker",
                        f"job {job} stage=extract rows={rng.randint(5000, 20000)} "
                        f"duration_ms={rng.randint(400, 1200)}",
                    )
                )

    events.sort(key=lambda e: e.timestamp)
    return events


def format_syslog(event: LogEvent) -> str:
    """Render an event in the syslog-ish format :mod:`logroot.ingest` parses."""
    return (
        f"{event.timestamp.isoformat()} {event.level} "
        f"{event.service} {event.message}"
    )


def write_logs(events: list[LogEvent], path: str) -> str:
    """Write events to ``path`` in syslog-ish format. Returns the path."""
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(format_syslog(event) + "\n")
    return path
