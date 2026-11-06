"""Bounded, deterministic indicators. No rule executes commands or network actions."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
import json
import math
import re

from .database import as_utc
from .schemas import Evidence, RuleFinding


@dataclass
class Record:
    data: dict
    source: str


def parse_records(raw_data: str) -> list[Record]:
    try:
        payload = json.loads(raw_data)
        items = payload.get("events", [payload]) if isinstance(payload, dict) else payload
        if isinstance(items, list):
            return [Record(item, f"raw_data.events[{i}]" if isinstance(payload, dict) and "events" in payload else f"raw_data[{i}]" if isinstance(payload, list) else "raw_data")
                    for i, item in enumerate(items[:200]) if isinstance(item, dict)]
    except (ValueError, TypeError, RecursionError):
        pass
    # A documented key=value format is also supported. Arbitrary prose is not
    # interpreted as evidence of failed logins or a verified VPN.
    records = []
    for index, line in enumerate(raw_data.splitlines()[:200]):
        try:
            item = json.loads(line)
        except (ValueError, TypeError, RecursionError):
            pairs = re.findall(r'(\w+)=("[^"\n]*"|\'[^\'\n]*\'|[^\s]+)', line)
            item = {key: value.strip('"\'') for key, value in pairs}
        if isinstance(item, dict):
            records.append(Record(item, f"raw_data.line[{index + 1}]"))
    return records


def timestamp(data: dict) -> datetime | None:
    value = data.get("timestamp", data.get("at"))
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return as_utc(result) if result.tzinfo is not None and result.year >= 1970 else None
    except (ValueError, TypeError, OverflowError):
        return None


def number(value, default=0) -> float:
    try:
        result = float(value) if not isinstance(value, bool) else float(default)
        return result if math.isfinite(result) else float(default)
    except (ValueError, TypeError, OverflowError):
        return float(default)


def event_name(data: dict) -> str:
    return str(data.get("event_type", data.get("type", data.get("event", "")))).lower()


def account_name(data: dict) -> str:
    value = data.get("user")
    return value.strip() if isinstance(value, str) and 1 <= len(value.strip()) <= 80 else ""


def record_ip(data: dict, fallback: str) -> str:
    try:
        return str(ip_address(data.get("source_ip", fallback)))
    except ValueError:
        return ""


def evaluate_rules(raw_data: str, source_ip: str, trusted_networks=("192.168.0.0/16",)) -> list[RuleFinding]:
    records = parse_records(raw_data)
    findings = []

    def add(rule_id, description, evidence, *, kind="indicator", facts=None):
        findings.append(RuleFinding(id=rule_id, description=description, kind=kind,
                                    evidence=evidence[:12], facts=facts or {}))

    groups = defaultdict(list)
    successes = []
    for record in records:
        data = record.data
        name, at = event_name(data), timestamp(data)
        ip, user = record_ip(data, source_ip), account_name(data)
        if not at or not ip:
            continue
        if name in {"failed_login", "login_failed", "auth_failure"}:
            count, window = number(data.get("count", 1)), number(data.get("window_seconds", 0), -1)
            if count.is_integer() and 1 <= count <= 1_000_000 and 0 <= window <= 300:
                groups[(ip, user)].append((at, at - timedelta(seconds=window), int(count), record))
        if name in {"successful_login", "login_success", "auth_success"}:
            successes.append((ip, user, at, record))

    best = None
    for (ip, user), failures in groups.items():
        for end, _, _, _ in failures:
            window = [item for item in failures if end - timedelta(seconds=300) <= item[1] <= item[0] <= end]
            count = sum(item[2] for item in window)
            if count >= 10 and (best is None or count > best[0]):
                best = (count, ip, user, window)
    if best:
        count, ip, user, window = best
        add("R001", "Серия неудачных входов: возможный Brute Force", [
            Evidence(description=f"{item[2]} неудачных входов; IP {ip}; пользователь {user or 'не указан'}; конец окна {item[0].isoformat()}", source=item[3].source)
            for item in window
        ], facts={"failed_count": count, "window_seconds": 300, "user": user, "source_ip": ip})

    for ip, user, at, success in successes:
        if not user:
            continue
        window = [item for item in groups[(ip, user)] if at - timedelta(seconds=300) <= item[1] <= item[0] < at]
        count = sum(item[2] for item in window)
        if count >= 10:
            add("R002", "Успешный вход после серии неудачных: возможная компрометация", [
                Evidence(description=f"{count} неудачных входов перед успешным для {user} с {ip}", source=window[0][3].source),
                Evidence(description=f"Успешный вход в {at.isoformat()} для того же пользователя и IP", source=success.source),
            ], facts={"failed_count": count, "user": user, "source_ip": ip, "privileged_account_name": user.lower() in {"admin", "administrator", "root"}})
            break

    command_candidates = [(value, record.source) for record in records
                          if isinstance((value := record.data.get("command", record.data.get("command_line"))), str)]
    # Never concatenate structured records to infer a single process invocation.
    if not command_candidates:
        try:
            structured = isinstance(json.loads(raw_data), (dict, list))
        except (ValueError, TypeError, RecursionError):
            fields = {"command", "command_line", "type", "event_type", "event", "source_ip", "user", "timestamp", "at", "corporate_vpn", "ports", "dest_port"}
            structured = any(fields.intersection(record.data) for record in records)
        if not structured:
            command_candidates = [(line, f"raw_data.line[{index + 1}]") for index, line in enumerate(raw_data.splitlines())]
    for command, source in command_candidates:
        if not re.search(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b", command, re.I):
            continue
        patterns = {
            "encoded_command": r"-(?:enc(?:odedcommand)?|e)\s+\S+",
            "download": r"\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|webclient)\b",
            "dynamic_execution": r"\b(?:iex|invoke-expression)\b",
            "policy_bypass": r"-(?:executionpolicy|ep)\s+bypass\b",
            "hidden_window": r"-(?:windowstyle|w)\s+hidden\b",
        }
        features = [name for name, pattern in patterns.items() if re.search(pattern, command, re.I)]
        if features:
            add("R003", "PowerShell с потенциально опасными параметрами", [
                Evidence(description=f"Выявленный параметр команды: {name}", source=source) for name in features
            ], facts={"features": features})
            break

    scans = defaultdict(list)
    for record in records:
        data, at = record.data, timestamp(record.data)
        if event_name(data) not in {"connection", "network_connection", "port_scan"} or not at:
            continue
        seconds = number(data.get("window_seconds", 0), -1)
        if not 0 <= seconds <= 60:
            continue
        values = data.get("ports", [data.get("dest_port")])
        if not isinstance(values, list):
            continue
        ports = {int(number(p)) for p in values[:1024] if 1 <= number(p) <= 65535 and number(p).is_integer()}
        ip = record_ip(data, source_ip)
        if ports and ip:
            scans[ip].append((at, at - timedelta(seconds=seconds), ports, record))
    for ip, entries in scans.items():
        matched = False
        for end, _, _, _ in entries:
            window = [row for row in entries if end - timedelta(seconds=60) <= row[1] <= row[0] <= end]
            ports = set().union(*(row[2] for row in window))
            if len(ports) >= 20:
                add("R004", "Соединения с множеством портов за 60 секунд: возможное сканирование", [
                    Evidence(description=f"Порты: {', '.join(map(str, sorted(row[2])))[:450]}", source=row[3].source) for row in window
                ], facts={"distinct_ports": len(ports), "window_seconds": 60, "source_ip": ip})
                matched = True
                break
        if matched:
            break

    address = ip_address(source_ip)
    for cidr in trusted_networks:
        if address in ip_network(cidr):
            add("R005", "IP входит в настроенную доверенную сеть; это не доказывает безопасность", [
                Evidence(description=f"{source_ip} входит в {cidr}", source="alert.source_ip")
            ], kind="context", facts={"network": cidr})
            break

    for record in records:
        vpn = record.data.get("corporate_vpn")
        if (isinstance(vpn, dict) and vpn.get("verified") is True
                and isinstance(vpn.get("verification_source"), str) and vpn["verification_source"].strip()
                and record_ip(record.data, source_ip) == source_ip):
            add("R006", "В логе указан подтвержденный корпоративный VPN", [
                Evidence(description=f"Источник подтверждения: {vpn['verification_source'][:150]}; аттестация из входных данных требует доверенного источника", source=record.source + ".corporate_vpn")
            ], kind="context", facts={"verification_source": vpn["verification_source"][:150]})
            break
    return findings
