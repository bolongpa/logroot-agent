"""Render a RootCauseReport + Incident as Markdown."""

from __future__ import annotations

from .agent import RootCauseReport
from .detect import Incident


def render_markdown(report: RootCauseReport, incident: Incident) -> str:
    lines = [
        f"# Root-cause analysis — `{incident.id}`",
        "",
        f"**Service:** `{incident.service}` · **Severity:** {incident.severity} · "
        f"**Kind:** `{incident.kind}`",
        f"**Window:** {incident.window.start.isoformat()} → {incident.window.end.isoformat()}",
        "",
        "## Summary",
        "",
        report.summary or "_No summary produced._",
        "",
        "## Evidence timeline",
        "",
    ]
    if report.evidence_timeline:
        lines.extend(f"- {item}" for item in report.evidence_timeline)
    else:
        lines.append("_No evidence collected._")
    lines += [
        "",
        "## Likely root cause",
        "",
        report.root_cause or "_Unknown._",
        "",
        f"_Confidence: {report.confidence:.0%}_",
        "",
        "## Suggested remediations",
        "",
    ]
    if report.remediations:
        lines.extend(f"{i}. {step}" for i, step in enumerate(report.remediations, 1))
    else:
        lines.append("_None suggested._")
    lines += [
        "",
        "---",
        "",
        "### Detector context",
        "",
        f"- **Signature:** `{incident.signature}`",
        f"- **Description:** {incident.description}",
        f"- **Events in incident:** {incident.count}",
    ]
    if incident.sample_events:
        lines += ["", "<details>", "<summary>Sample events</summary>", "", "```"]
        for event in incident.sample_events[:5]:
            lines.append(
                f"{event.timestamp.isoformat()} {event.level} "
                f"{event.service} {event.message}"
            )
        lines += ["```", "</details>"]
    lines.append("")
    return "\n".join(lines)
