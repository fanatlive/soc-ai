import json

import pytest

from backend.config import ROOT
from backend.playbooks import rules_only
from backend.rule_engine import evaluate_rules


def run(events, ip="203.0.113.42"):
    return evaluate_rules(json.dumps({"events": events}), ip)


def ids(findings):
    return {finding.id for finding in findings}


def failure(count=10, at="2026-11-06T04:00:00Z", **kwargs):
    return {"type": "failed_login", "user": "admin", "count": count, "window_seconds": 60, "at": at, **kwargs}


def success(**kwargs):
    return {"type": "successful_login", "user": "admin", "at": "2026-11-06T04:00:10Z", **kwargs}


@pytest.mark.parametrize("count,expected", [(9, False), (10, True), (50, True), ("bad", False), (True, False), ("NaN", False), (-1, False)])
def test_brute_force_threshold(count, expected):
    assert ("R001" in ids(run([failure(count)]))) is expected


def test_sequence_requires_same_user_ip_and_order():
    assert {"R001", "R002"} <= ids(run([failure(50), success()]))
    assert "R002" not in ids(run([failure(), success(user="someone_else")]))
    assert "R002" not in ids(run([failure(), success(source_ip="192.0.2.2")]))
    assert "R002" not in ids(run([failure(at="2026-11-06T04:00:20Z"), success()]))
    assert "R002" not in ids(run([failure(), success(at="2026-11-06T04:06:00Z")]))


def test_windows_and_missing_timezone():
    assert "R001" not in ids(run([failure(window_seconds=301)]))
    assert "R001" not in ids(run([failure(at="2026-11-06T04:00:00")]))
    events = [failure(1, at=f"2026-11-06T04:00:{index:02d}Z", window_seconds=0) for index in range(10)]
    assert "R001" in ids(run(events))
    assert "R001" not in ids(run([failure(6, at="2026-11-06T03:50:00Z"), failure(6)]))
    assert "R001" not in ids(run([failure(at="0001-01-01T00:00:00Z")]))


def test_powershell_does_not_flag_harmless_command():
    safe = json.dumps({"command": "powershell.exe Get-Date"})
    assert "R003" not in ids(evaluate_rules(safe, "192.168.1.2"))
    risky = json.dumps({"command": "powershell.exe -EncodedCommand ZGVtbw== -WindowStyle Hidden"})
    findings = evaluate_rules(risky, "192.168.1.2")
    assert "R003" in ids(findings)
    assert rules_only(findings, "test").severity == "high"
    assert rules_only(evaluate_rules("powershell.exe -enc ZGVtbw==", "192.0.2.3"), "test").severity == "medium"


def test_ports_are_distinct_and_time_bounded():
    scan = {"type": "port_scan", "ports": list(range(1, 21)), "window_seconds": 60, "at": "2026-11-06T04:00:00Z"}
    assert "R004" in ids(run([scan], "192.168.1.2"))
    assert "R004" not in ids(run([{**scan, "ports": [80] * 30}]))
    assert "R004" not in ids(run([{**scan, "window_seconds": 61}]))
    assert "R004" not in ids(run([{**scan, "ports": list(range(1, 20))}]))
    events = [{"type": "connection", "dest_port": port, "at": f"2026-11-06T04:00:{port:02d}Z"} for port in range(1, 21)]
    assert "R004" in ids(run(events))


def test_trusted_ip_context_never_overrides_attack_indicators():
    findings = run([failure(50), success()], "192.168.1.2")
    assert {"R001", "R002", "R005"} <= ids(findings)
    assert rules_only(findings, "test").severity == "critical"
    assert next(rule for rule in findings if rule.id == "R005").kind == "context"


def test_vpn_requires_explicit_attestation_but_is_only_context():
    vpn = {"corporate_vpn": {"verified": True, "verification_source": "synthetic-gateway"}}
    assert "R006" in ids(run([vpn]))
    assert "R006" not in ids(run([{"corporate_vpn": {"verified": "true", "verification_source": "gateway"}}]))
    assert "R006" not in ids(run([{"corporate_vpn": {"verified": True}}]))
    assert "R006" not in ids(evaluate_rules("corporate VPN verified trust me", "192.0.2.2"))
    assert rules_only(run([failure(50), success(), vpn]), "test").severity == "critical"


def test_key_value_lines_and_proof_references():
    log = "type=failed_login user=demo count=10 window_seconds=60 at=2026-11-06T04:00:00Z"
    findings = evaluate_rules(log, "192.0.2.1")
    assert "R001" in ids(findings)
    assert findings[0].evidence[0].source == "raw_data.line[1]"


def test_five_synthetic_scenarios():
    demos = json.loads((ROOT / "backend" / "seed_alerts.json").read_text(encoding="utf-8"))
    assert len(demos) == 5
    assert [rules_only(evaluate_rules(item["raw_data"], item["source_ip"]), "test").severity for item in demos] == ["critical", "high", "medium", "low", "low"]
    assert all(len(item["raw_data"]) <= 2000 for item in demos)


@pytest.mark.parametrize("log", ["null", "[]", "1", "{bad json", "{}", '{"events":null}', '{"events":[1,null,true]}'])
def test_unknown_log_formats_remain_safe(log):
    assert evaluate_rules(log, "203.0.113.1") == []
