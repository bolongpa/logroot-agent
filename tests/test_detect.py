"""Tests for logroot.detect: the injected incident must be found."""

from logroot.detect import detect_incidents, signature_of
from logroot.simulate import generate_logs


def test_signature_normalization():
    a = signature_of("db query timeout after 30000ms job_id=job-0007")
    b = signature_of("db query timeout after 30000ms job_id=job-0042")
    assert a == b
    assert "job-0007" not in a


def test_detects_injected_error_burst():
    events = generate_logs()
    incidents = detect_incidents(events)
    bursts = [i for i in incidents if i.kind == "error_burst" and i.service == "etl-worker"]
    assert bursts, f"expected an etl-worker error burst, got: {[(i.kind, i.service) for i in incidents]}"
    burst = bursts[0]
    assert "timeout" in burst.signature
    assert burst.severity in {"medium", "high"}
    assert burst.count >= 5
    assert burst.sample_events


def test_detects_injected_latency_spike():
    events = generate_logs()
    incidents = detect_incidents(events)
    spikes = [i for i in incidents if i.kind == "latency_spike" and i.service == "db-proxy"]
    assert spikes, f"expected a db-proxy latency spike, got: {[(i.kind, i.service) for i in incidents]}"
    assert "p95" in spikes[0].signature


def test_detects_new_error_signature():
    events = generate_logs()
    incidents = detect_incidents(events)
    new = [i for i in incidents if i.kind == "new_error_signature" and i.service == "etl-worker"]
    assert new, "expected a brand-new etl-worker error signature"


def test_no_incidents_without_injection():
    events = generate_logs(incident=None)
    incidents = detect_incidents(events)
    high = [i for i in incidents if i.severity == "high"]
    assert not high, f"unexpected high-severity incidents on clean logs: {high}"


def test_empty_input():
    assert detect_incidents([]) == []
