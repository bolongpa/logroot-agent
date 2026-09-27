"""Command-line interface: ``logroot demo`` and ``logroot analyze``."""

from __future__ import annotations

import argparse
import sys
import tempfile

from .agent import FakeLLM, OpenAICompatibleLLM, analyze_incident
from .detect import Incident, detect_incidents
from .ingest import parse_file
from .report import render_markdown
from .simulate import generate_logs, write_logs


def _pick_incident(incidents: list[Incident]) -> Incident | None:
    """Prefer the etl-worker error burst (the demo's headline incident)."""
    if not incidents:
        return None
    for incident in incidents:
        if incident.kind == "error_burst" and incident.service == "etl-worker":
            return incident
    return incidents[0]


def _make_llm(choice: str):
    if choice == "openai":
        return OpenAICompatibleLLM()
    return FakeLLM()


def _run(events, llm_choice: str) -> int:
    incidents = detect_incidents(events)
    print(f"Detected {len(incidents)} incident(s):")
    for incident in incidents:
        print(f"  - [{incident.severity}] {incident.kind} {incident.service}: {incident.description}")
    incident = _pick_incident(incidents)
    if incident is None:
        print("No incidents detected; nothing to analyze.")
        return 1
    print(f"\nAnalyzing {incident.id} with llm={llm_choice} ...\n")
    llm = _make_llm(llm_choice)
    report = analyze_incident(incident, llm, events)
    print(render_markdown(report, incident))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    events = generate_logs(seed=args.seed)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", prefix="logroot-demo-", delete=False
    ) as fh:
        path = fh.name
    write_logs(events, path)
    print(f"Generated {len(events)} synthetic log events -> {path}")
    print("Incident injected: downstream DB slowdown at 21:20 UTC (+8 min)\n")
    parsed = parse_file(path)
    return _run(parsed, args.llm)


def cmd_analyze(args: argparse.Namespace) -> int:
    events = parse_file(args.logfile)
    if not events:
        print(f"No parseable log events found in {args.logfile}", file=sys.stderr)
        return 1
    print(f"Parsed {len(events)} events from {args.logfile}")
    return _run(events, args.llm)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logroot",
        description="LLM agent for log anomaly detection and root-cause analysis.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="End-to-end demo on synthetic logs.")
    demo.add_argument("--llm", choices=["fake", "openai"], default="fake",
                      help="LLM backend (fake = offline scripted stand-in)")
    demo.add_argument("--seed", type=int, default=42, help="Random seed for the simulator")
    demo.set_defaults(func=cmd_demo)

    analyze = sub.add_parser("analyze", help="Analyze a real log file.")
    analyze.add_argument("logfile", help="Path to a log file (syslog-ish or JSON-lines)")
    analyze.add_argument("--llm", choices=["fake", "openai"], default="fake",
                         help="LLM backend (fake = offline scripted stand-in)")
    analyze.set_defaults(func=cmd_analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
