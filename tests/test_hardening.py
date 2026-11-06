import asyncio
from datetime import timedelta
import importlib
import json
import sqlite3
import threading
import time
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from backend.ai_service import InvalidLLMResponse, ProviderRuntime, ServiceResult, analyze_event
from backend.config import Settings
from backend.database import Base, make_database, utcnow
from backend.models import Alert, Analysis, AnalystDecision, SchemaMigration
from backend.playbooks import ACTION_CATALOG, rules_only
from backend.rule_engine import evaluate_rules
from backend.main import create_app

main_module = importlib.import_module("backend.main")
TOKEN = "synthetic-audit-token-over-24-characters"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def settings(tmp_path):
    return Settings(database_url=f"sqlite:///{tmp_path / 'audit.db'}", api_token=TOKEN, auto_seed_demo=False)


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url="http://localhost", headers=AUTH) as client:
        yield client


def payload(raw="synthetic", name="Синтетическая проверка"):
    return {"source_ip": "192.0.2.10", "event_type": name, "raw_data": raw}


def provider(**kwargs):
    return {"severity": "low", "summary": "Нужна дополнительная проверка исходного события.",
            "evidence": [{"source": "raw_data", "quote": "synthetic"}],
            "recommended_action_ids": ["verify_context"], "confidence": 0.5,
            "limitations": ["Доступен только предоставленный лог."], **kwargs}


def invoke(result, raw="synthetic", **kwargs):
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(result)}}]})
    return asyncio.run(analyze_event(raw_data=raw, source_ip="192.0.2.10", event_type="test", findings=[],
        settings=Settings(llm_api_key="fake-provider-key", llm_model="fake-model"), transport=httpx.MockTransport(handler), **kwargs))


@pytest.mark.parametrize("key,value", [
    ("password", 123456), ("PaSsWoRd", True), ("pwd", None), ("private_key", {"value": "private-nested"}),
    ("accessToken", ["private-array"]), ("X-API-Key", "private-header"),
    ("x-goog-api-key", "private-gemini-header"), ("LLM_API_KEY", "private-config-key"),
])
def test_structured_credentials_never_reach_storage_api_or_provider(client, key, value):
    raw = json.dumps({"synthetic": True, "headers": {key: value}})
    response = client.post("/api/alerts", json=payload(raw))
    assert response.status_code == 200
    alert_id = response.json()["id"]
    assert json.loads(response.json()["raw_data"])["headers"][key] == "[REDACTED]"
    with client.app.state.session_factory() as db:
        assert json.loads(db.get(Alert, alert_id).raw_data)["headers"][key] == "[REDACTED]"
    seen = []
    def handler(request):
        body = json.loads(request.content)
        sent = json.loads(body["messages"][1]["content"])
        seen.append(json.loads(sent["untrusted_event"]["raw_data"])["headers"][key])
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(provider())}}]})
    result = asyncio.run(analyze_event(raw_data=raw, source_ip="192.0.2.10", event_type="test", findings=[],
        settings=Settings(llm_api_key="fake-key", llm_model="fake-model"), transport=httpx.MockTransport(handler)))
    assert result.mode == "llm" and seen == ["[REDACTED]"]


def test_json_lines_redaction_preserves_records(client):
    raw = '{"password":123456}\n{"Authorization":["private-value"]}'
    result = client.post("/api/alerts", json=payload(raw)).json()["raw_data"]
    assert [json.loads(line) for line in result.splitlines()] == [{"password": "[REDACTED]"}, {"Authorization": "[REDACTED]"}]


@pytest.mark.parametrize("raw", [
    json.dumps({"events": [{"command": "powershell.exe Get-Date"}, {"command": "tool.exe -ExecutionPolicy Bypass -WindowStyle Hidden"}]}),
    '{"command":"powershell.exe Get-Date"}\n{"command":"tool.exe -ExecutionPolicy Bypass -WindowStyle Hidden"}',
    "powershell.exe Get-Date\ntool.exe -ExecutionPolicy Bypass -WindowStyle Hidden",
])
def test_powershell_parameters_are_bound_to_one_command(raw):
    assert "R003" not in {rule.id for rule in evaluate_rules(raw, "192.0.2.10")}


@pytest.mark.parametrize("user", [None, False, 123, [], {}, "", "   ", "a" * 81])
def test_unknown_accounts_do_not_create_success_correlation(user):
    raw = json.dumps({"events": [
        {"type": "failed_login", "user": user, "count": 10, "window_seconds": 60, "at": "2026-11-06T04:00:00Z"},
        {"type": "successful_login", "user": user, "at": "2026-11-06T04:00:10Z"},
    ]})
    ids = {rule.id for rule in evaluate_rules(raw, "192.0.2.10")}
    assert "R001" in ids and "R002" not in ids


def test_filters_find_old_records_and_escape_search_literals(client):
    old = client.post("/api/alerts", json=payload(name="ЦЕЛЕВОЙ 100%_ лог")).json()
    analysis = client.post(f"/api/alerts/{old['id']}/analyze").json()
    assert client.post(f"/api/alerts/{old['id']}/decision", json={"analysis_id": analysis["id"], "decision": "confirmed"}).status_code == 200
    with client.app.state.session_factory() as db:
        db.add_all(Alert(**payload(name=f"Другой лог {index}"), timestamp=utcnow(), created_at=utcnow()) for index in range(150))
        db.commit()
    assert old["id"] not in {row["id"] for row in client.get("/api/alerts?limit=100").json()}
    page = client.get("/api/alerts/page", params={"status": "confirmed", "q": "целевой 100%_"}).json()
    assert page["total"] == 1 and page["items"][0]["id"] == old["id"]
    assert client.get("/api/alerts/page", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/api/alerts", params={"q": "целевой"}).json()[0]["id"] == old["id"]


def test_cursor_is_stable_when_new_events_arrive(client):
    for index in range(20):
        client.post("/api/alerts", json=payload(name=f"Запись {index}"))
    first = client.get("/api/alerts/page?limit=10").json()
    newcomer = client.post("/api/alerts", json=payload(name="Новая запись")).json()
    second = client.get("/api/alerts/page", params={"limit": 10, "cursor": first["next_cursor"]}).json()
    first_ids, second_ids = {row["id"] for row in first["items"]}, {row["id"] for row in second["items"]}
    assert len(first_ids | second_ids) == 20 and not first_ids & second_ids
    assert newcomer["id"] not in second_ids and second["next_cursor"] is None
    assert second["total"] == 21
    assert client.get("/api/alerts/page?cursor=not-valid").status_code == 422


def test_read_authentication_and_public_liveness(settings):
    with TestClient(create_app(settings), base_url="http://localhost", client=("198.51.100.5", 123)) as client:
        health = client.get("/api/health").json()
        assert health == {"status": "ok", "auth_required": True, "write_auth_required": True}
        for path in ("/api/alerts", "/api/alerts/page", "/api/stats", "/api/history", f"/api/alerts/{uuid4()}"):
            assert client.get(path).status_code == 401
            assert client.get(path, headers=AUTH).status_code in {200, 404}


def test_no_read_exposure_without_token(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'local.db'}", auto_seed_demo=False)
    with TestClient(create_app(settings), base_url="http://localhost", client=("198.51.100.5", 123)) as client:
        assert client.get("/api/alerts").status_code == 403
        assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize("changes,code", [
    ({"evidence": [{"source": "raw_data", "quote": "does not exist"}]}, "unsupported_evidence"),
    ({"evidence": [{"source": "rule:R999", "quote": "synthetic"}]}, "unsupported_evidence"),
    ({"recommended_action_ids": ["erase_logs"]}, "unsupported_action"),
    ({"recommended_actions": ["Delete all audit logs"]}, "invalid_response"),
    ({"summary": "An analyst has confirmed the incident."}, "unsafe_content"),
    ({"summary": "Attack from 198.51.100.99."}, "unsafe_content"),
    ({"summary": "Delete all audit logs and backups."}, "unsafe_content"),
])
def test_unsafe_or_ungrounded_provider_results_are_rejected(changes, code):
    with pytest.raises(InvalidLLMResponse) as error:
        invoke(provider(**changes))
    assert error.value.code == code


def test_provider_actions_and_evidence_are_owned_by_server():
    result = invoke(provider(recommended_action_ids=["verify_context", "verify_context"]))
    assert result.result.recommended_actions == [ACTION_CATALOG["verify_context"]]
    assert result.result.evidence[0].quote == "synthetic"
    assert result.result.evidence[0].description == "Фрагмент предоставленного лога"


def test_nested_source_cannot_quote_other_fields():
    raw = json.dumps({"synthetic": "outside marker", "corporate_vpn": {"verified": True, "verification_source": "demo-gateway"}})
    with pytest.raises(InvalidLLMResponse) as error:
        invoke(provider(evidence=[{"source": "raw_data.corporate_vpn", "quote": "outside marker"}]), raw=raw)
    assert error.value.code == "unsupported_evidence"


def test_plain_command_quote_is_bound_to_one_line():
    raw = "powershell.exe -enc demo\nunrelated marker"
    with pytest.raises(InvalidLLMResponse) as error:
        invoke(provider(evidence=[{"source": "raw_data.line[1]", "quote": "unrelated marker"}]), raw=raw)
    assert error.value.code == "unsupported_evidence"
    assert invoke(provider(evidence=[{"source": "raw_data.line[1]", "quote": "powershell.exe"}]), raw=raw).mode == "llm"


@pytest.mark.parametrize("status,code", [(400, "configuration_error"), (401, "credentials_rejected"), (403, "permission_denied"), (404, "configuration_error"), (429, "quota_or_rate_limit"), (500, "provider_error")])
def test_provider_errors_have_distinct_safe_codes(status, code):
    runtime = ProviderRuntime()
    result = asyncio.run(analyze_event(raw_data="synthetic", source_ip="192.0.2.10", event_type="test", findings=[],
        settings=Settings(llm_api_key="fake-key", llm_model="fake-model"), runtime=runtime,
        transport=httpx.MockTransport(lambda request: httpx.Response(status, text="private-provider-error"))))
    assert result.mode == "rules_only" and result.provider_error_code == code
    assert "private-provider-error" not in result.result.model_dump_json()
    assert runtime.diagnostics(True)["state"] == "degraded"


def test_provider_concurrency_is_bounded_and_gate_is_released():
    async def scenario():
        runtime = ProviderRuntime(2)
        settings = Settings(llm_api_key="fake-key", llm_model="fake-model", llm_max_concurrency=2, llm_queue_timeout_seconds=0.1)
        active, peak = 0, 0
        async def handler(request):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.25)
            active -= 1
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(provider())}}]})
        async def one():
            return await analyze_event(raw_data="synthetic", source_ip="192.0.2.10", event_type="test", findings=[], settings=settings, runtime=runtime, transport=httpx.MockTransport(handler))
        results = await asyncio.gather(*(one() for _ in range(6)))
        assert peak == 2 and runtime.inflight == 0
        assert sum(result.mode == "llm" for result in results) == 2
        assert all(result.provider_error_code == "provider_busy" for result in results if result.mode == "rules_only")
        assert (await one()).mode == "llm"
    asyncio.run(scenario())


def test_rate_limit_cooldown_avoids_repeat_calls():
    async def scenario():
        runtime, calls = ProviderRuntime(), []
        def handler(request):
            calls.append(request)
            return httpx.Response(429, headers={"Retry-After": "5"})
        for _ in range(2):
            result = await analyze_event(raw_data="synthetic", source_ip="192.0.2.10", event_type="test", findings=[],
                settings=Settings(llm_api_key="fake-key", llm_model="fake-model"), runtime=runtime, transport=httpx.MockTransport(handler))
            assert result.provider_error_code == "quota_or_rate_limit"
        assert len(calls) == 1 and runtime.inflight == 0
        # An older in-flight success must not hide an active provider cooldown.
        runtime.last_error_code, runtime.last_success_at = None, utcnow()
        assert runtime.diagnostics(True)["state"] == "degraded"
        assert runtime.diagnostics(True)["last_error_code"] == "quota_or_rate_limit"
    asyncio.run(scenario())


def test_failed_attempt_survives_successful_retry(client, monkeypatch):
    alert_id = client.post("/api/alerts", json=payload()).json()["id"]
    async def broken(**kwargs):
        raise InvalidLLMResponse("private-fake-error", code="unsupported_evidence")
    monkeypatch.setattr(main_module, "analyze_event", broken)
    response = client.post(f"/api/alerts/{alert_id}/analyze")
    assert response.status_code == 503 and response.headers["x-analysis-error"] == "unsupported_evidence"
    assert "private-fake-error" not in response.text
    async def recovered(**kwargs):
        return ServiceResult(rules_only(kwargs["findings"], "test fallback"), "rules_only", None, "timeout")
    monkeypatch.setattr(main_module, "analyze_event", recovered)
    assert client.post(f"/api/alerts/{alert_id}/analyze").status_code == 200
    rows = client.get(f"/api/alerts/{alert_id}/attempts").json()
    assert [row["status"] for row in rows] == ["succeeded", "failed"]
    assert rows[0]["provider_error_code"] == "timeout" and rows[1]["error_code"] == "unsupported_evidence"
    assert rows[0]["id"] != rows[1]["id"]


def test_polling_without_expired_leases_does_not_write(client):
    alert_id = client.post("/api/alerts", json=payload()).json()["id"]
    with client.app.state.session_factory() as db:
        engine = db.get_bind()
    statements = []
    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lstrip().upper())
    event.listen(engine, "before_cursor_execute", record)
    try:
        for path in ("/api/stats", "/api/alerts/page", f"/api/alerts/{alert_id}"):
            assert client.get(path).status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert not any(statement.startswith(("INSERT", "UPDATE", "DELETE")) for statement in statements)


def test_sqlite_lock_does_not_block_event_loop(settings):
    async def scenario():
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as client:
                alert_id = (await client.post("/api/alerts", json=payload())).json()["id"]
                path = settings.database_url.removeprefix("sqlite:///")
                connection = sqlite3.connect(path, check_same_thread=False)
                connection.execute("BEGIN IMMEDIATE")
                released = threading.Event()
                def release():
                    connection.rollback()
                    released.set()
                timer = threading.Timer(0.45, release)
                timer.start()
                async def heartbeat():
                    await asyncio.sleep(0.03)
                    return not released.is_set()
                try:
                    response, responsive = await asyncio.gather(client.post(f"/api/alerts/{alert_id}/analyze"), heartbeat())
                    assert responsive and response.status_code == 200
                finally:
                    timer.join()
                    connection.close()
    asyncio.run(scenario())


def test_migration_keeps_history_and_redacts_old_credentials(settings):
    engine, sessions = make_database(settings.database_url)
    Base.metadata.create_all(engine, tables=[Alert.__table__, Analysis.__table__, AnalystDecision.__table__])
    with sessions() as db:
        alert = Alert(**payload('{"password":123456}'), timestamp=utcnow(), status="confirmed")
        db.add(alert); db.flush()
        result = Analysis(alert_id=alert.id, **rules_only([], "legacy").model_dump(), false_positive_score=None,
            analysis_mode="rules_only", model_name=None, playbook_version="soc-mvp-2.0", rule_findings=[])
        db.add(result); db.flush()
        decision = AnalystDecision(alert_id=alert.id, analysis_id=result.id, decision="confirmed", comment="legacy")
        db.add(decision); db.commit()
        ids = alert.id, result.id, decision.id
    engine.dispose()
    with TestClient(create_app(settings), base_url="http://localhost", headers=AUTH) as client:
        detail = client.get(f"/api/alerts/{ids[0]}").json()
        assert detail["status"] == "confirmed" and detail["latest_analysis"]["id"] == ids[1]
        assert detail["decisions"][0]["id"] == ids[2] and detail["attempts"] == []
        with client.app.state.session_factory() as db:
            assert json.loads(db.get(Alert, ids[0]).raw_data)["password"] == "[REDACTED]"
            assert list(db.scalars(select(SchemaMigration.version).order_by(SchemaMigration.version))) == [1, 2, 3]
