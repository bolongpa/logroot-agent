"""Tests for the agentic loop with FakeLLM. No network calls."""

from logroot.agent import FakeLLM, RootCauseReport, analyze_incident
from logroot.detect import detect_incidents
from logroot.report import render_markdown
from logroot.simulate import generate_logs


def _burst_incident():
    events = generate_logs()
    incidents = detect_incidents(events)
    incident = next(i for i in incidents if i.kind == "error_burst" and i.service == "etl-worker")
    return incident, events


def test_agent_calls_tools_then_produces_report():
    incident, events = _burst_incident()
    llm = FakeLLM()
    report = analyze_incident(incident, llm, events)

    # It must gather evidence with tools before writing the report.
    assert len(llm.calls) >= 2, f"expected >=2 tool calls, got {llm.calls}"
    names = [name for name, _ in llm.calls]
    assert "top_signatures" in names
    assert "service_timeline" in names
    assert "search_logs" in names

    # The report must have every expected section filled in.
    assert isinstance(report, RootCauseReport)
    assert report.incident_id == incident.id
    assert report.summary and "etl-worker" in report.summary
    assert len(report.evidence_timeline) >= 1
    assert report.root_cause
    assert 0.0 <= report.confidence <= 1.0
    assert len(report.remediations) >= 1


def test_agent_identifies_upstream_cause():
    incident, events = _burst_incident()
    report = analyze_incident(incident, FakeLLM(), events)
    text = (report.root_cause + " " + report.summary).lower()
    assert "db-proxy" in text or "database" in text, (
        "expected the report to point at the slow downstream DB, got: " + report.root_cause
    )


def test_report_renders_all_sections():
    incident, events = _burst_incident()
    report = analyze_incident(incident, FakeLLM(), events)
    md = render_markdown(report, incident)
    for section in ("## Summary", "## Evidence timeline", "## Likely root cause", "## Suggested remediations"):
        assert section in md, f"missing section {section}"
    assert incident.id in md
    assert "Confidence" in md


def test_agent_respects_step_budget():
    incident, events = _burst_incident()

    class ChattyLLM(FakeLLM):
        def chat(self, messages, tools):  # never finishes: always asks for one more tool
            return self._tool_call("top_signatures", {"window": "", "n": 5})

    report = analyze_incident(incident, ChattyLLM(), events, max_steps=3)
    assert report.confidence <= 0.2  # honest low-confidence fallback
    assert "step budget" in report.summary
