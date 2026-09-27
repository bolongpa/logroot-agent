"""Tests for logroot.ingest. No network, no I/O beyond tmp files."""

from logroot.ingest import parse_line, parse_lines, parse_file


def test_syslog_format():
    event = parse_line("2026-09-26T21:00:01Z ERROR etl-worker db query timeout after 30000ms")
    assert event is not None
    assert event.level == "ERROR"
    assert event.service == "etl-worker"
    assert event.message == "db query timeout after 30000ms"
    assert event.timestamp.year == 2026


def test_syslog_lowercase_level_normalized():
    event = parse_line("2026-09-26T21:00:01Z warn db-proxy slow query")
    assert event is not None
    assert event.level == "WARN"


def test_json_lines_format():
    event = parse_line(
        '{"timestamp": "2026-09-26T21:00:01Z", "level": "ERROR", '
        '"service": "api-gateway", "msg": "upstream 502"}'
    )
    assert event is not None
    assert event.level == "ERROR"
    assert event.service == "api-gateway"
    assert event.message == "upstream 502"


def test_json_alias_keys():
    event = parse_line(
        '{"time": "2026-09-26T21:00:01+00:00", "severity": "info", '
        '"app": "db-proxy", "message": "query OK"}'
    )
    assert event is not None
    assert event.level == "INFO"
    assert event.service == "db-proxy"
    assert event.message == "query OK"


def test_json_epoch_timestamp():
    event = parse_line('{"timestamp": 1758926400, "level": "INFO", "service": "x", "msg": "ok"}')
    assert event is not None
    assert event.timestamp.year == 2025


def test_malformed_lines_are_skipped_not_raised():
    bad = [
        "",
        "   ",
        "not a log line at all !!!",
        "2026-09-26T21:00:01Z BOGUSLEVEL svc msg",  # unknown level
        '{"timestamp": "not-a-time", "msg": "x"}',  # bad timestamp
        "{not json at all",
        "2026-13-99T99:99:99Z INFO svc msg",  # impossible date
    ]
    for line in bad:
        assert parse_line(line) is None, f"expected None for {line!r}"
    events = parse_lines(bad + ["2026-09-26T21:00:01Z INFO svc ok"])
    assert len(events) == 1
    assert events[0].message == "ok"


def test_parse_file_roundtrip(tmp_path):
    path = tmp_path / "test.log"
    path.write_text(
        "2026-09-26T21:00:01Z INFO svc hello\n"
        "garbage line that should be skipped\n"
        '{"timestamp": "2026-09-26T21:00:02Z", "level": "ERROR", "service": "svc", "msg": "boom"}\n'
    )
    events = parse_file(str(path))
    assert len(events) == 2
    assert events[1].level == "ERROR"
