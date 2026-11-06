import asyncio
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import hmac
from ipaddress import ip_address
import json
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .ai_service import ERROR_MESSAGES, InvalidLLMResponse, ProviderRuntime, analyze_event
from .config import ROOT, Settings
from .database import as_utc, make_database, utcnow
from .migrations import migrate
from .models import Alert, Analysis, AnalysisAttempt, AnalystDecision
from .playbooks import PLAYBOOK_VERSION
from .rule_engine import evaluate_rules
from .schemas import (AlertCreate, AlertDetail, AlertOut, AlertPage, AnalysisOut, AttemptOut,
                      DecisionCreate, DecisionOut, HistoryEntry, StatsOut)
from .security import BodyLimitMiddleware, redact, scrub_tree

LEASE_SECONDS = 180
STATUS_PATTERN = "^(new|processing|analyzed|confirmed|false_positive|error)$"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    engine, sessions = make_database(settings.database_url)
    secrets = (settings.llm_api_key, settings.api_token)
    runtime = ProviderRuntime(settings.llm_max_concurrency)

    def clean(value):
        return scrub_tree(value, secrets)

    def recover_expired(db):
        cutoff = utcnow() - timedelta(seconds=LEASE_SECONDS)
        stale = and_(Alert.status == "processing", Alert.processing_started_at < cutoff)
        # Ordinary polling is read-only. Only genuine expired leases need writes.
        if db.scalar(select(Alert.id).where(stale).limit(1)) is None:
            return
        db.execute(update(Alert).where(stale).values(status="error", processing_token=None, processing_started_at=None))
        db.execute(update(AnalysisAttempt).where(AnalysisAttempt.status == "processing", AnalysisAttempt.started_at < cutoff)
                   .values(status="abandoned", error_code="lease_expired", completed_at=utcnow()))
        db.commit()

    def seed(db):
        payload = json.loads((ROOT / "backend" / "seed_alerts.json").read_text(encoding="utf-8"))
        created = 0
        for item in reversed(payload):
            alert_id = item.pop("id")
            validated = AlertCreate.model_validate(item)
            result = db.execute(insert(Alert).values(id=alert_id, **clean(validated.model_dump())).on_conflict_do_nothing(index_elements=["id"]))
            created += result.rowcount
        db.commit()
        return created

    @asynccontextmanager
    async def lifespan(_app):
        migrate(engine, secrets)
        with sessions() as db:
            recover_expired(db)
            if settings.auto_seed_demo:
                seed(db)
        yield
        engine.dispose()

    app = FastAPI(title="SOC AI Triage", version="2.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.session_factory = sessions
    app.state.settings = settings
    app.state.provider_runtime = runtime
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.allowed_origins),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization"],
                       expose_headers=["X-Request-ID", "X-Analysis-Error"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(BodyLimitMiddleware)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
        return response

    @app.exception_handler(RequestValidationError)
    async def input_error(_request, exc):
        safe_fields = {"body", "query", "path", "timestamp", "source_ip", "event_type", "raw_data", "alert_id", "analysis_id", "decision", "comment", "q", "limit", "offset", "cursor", "status"}
        fields = [".".join(str(part) if part in safe_fields else "unknown_field" for part in error["loc"]) for error in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Некорректные данные. Проверьте IP, время с часовым поясом, параметры и длину лога (1–2000 символов).", "fields": fields})

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_request, _exc):
        return JSONResponse(status_code=503, content={"detail": "Хранилище временно недоступно. Повторите запрос."})

    def database():
        with sessions() as db:
            yield db

    def local_client(request):
        try:
            return request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            return False

    def authenticated(request):
        if not settings.api_token:
            return local_client(request)
        supplied = request.headers.get("authorization", "")
        return hmac.compare_digest(supplied.encode(), f"Bearer {settings.api_token}".encode())

    def authorize_read(request: Request):
        if not authenticated(request):
            if settings.api_token:
                raise HTTPException(401, "Для доступа к событиям требуется токен аналитика", headers={"WWW-Authenticate": "Bearer"})
            raise HTTPException(403, "Внешний доступ к API требует настройки API_TOKEN")

    def authorize_write(request: Request):
        authorize_read(request)
        origin = request.headers.get("origin")
        if origin and origin not in settings.allowed_origins:
            raise HTTPException(403, "Origin не входит в список доверенных")

    reads, writes = [Depends(authorize_read)], [Depends(authorize_write)]

    def get_alert(db, alert_id):
        alert = db.get(Alert, str(alert_id))
        if alert is None:
            raise HTTPException(404, "Алерт не найден")
        return alert

    def analysis_out(analysis):
        fields = ("id", "alert_id", "severity", "false_positive_score", "summary", "evidence", "recommended_actions", "confidence", "limitations", "analysis_mode", "model_name", "playbook_version", "rule_findings")
        return AnalysisOut.model_validate(clean({**{key: getattr(analysis, key) for key in fields}, "created_at": as_utc(analysis.created_at)}))

    def latest(db, alert_id):
        return db.scalar(select(Analysis).where(Analysis.alert_id == alert_id).order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(1))

    def decision_out(decision):
        return DecisionOut(**clean({key: getattr(decision, key) for key in ("id", "alert_id", "analysis_id", "decision", "comment")}), created_at=as_utc(decision.created_at))

    def attempt_out(attempt):
        fields = ("id", "alert_id", "analysis_id", "status", "analysis_mode", "error_code", "provider_error_code")
        return AttemptOut(**{key: getattr(attempt, key) for key in fields}, started_at=as_utc(attempt.started_at),
                          completed_at=as_utc(attempt.completed_at) if attempt.completed_at else None)

    def alert_out(alert, analysis=None):
        return AlertOut(**clean({key: getattr(alert, key) for key in ("id", "source_ip", "event_type", "raw_data", "status")}),
                        timestamp=as_utc(alert.timestamp), created_at=as_utc(alert.created_at), latest_analysis=analysis_out(analysis) if analysis else None)

    def list_out(db, rows):
        results = {}
        if rows:
            ranked = select(Analysis.id, func.row_number().over(partition_by=Analysis.alert_id, order_by=[Analysis.created_at.desc(), Analysis.id.desc()]).label("position")).where(Analysis.alert_id.in_([row.id for row in rows])).subquery()
            for analysis in db.scalars(select(Analysis).join(ranked, Analysis.id == ranked.c.id).where(ranked.c.position == 1)):
                results[analysis.alert_id] = analysis
        return [alert_out(row, results.get(row.id)) for row in rows]

    def filtered_alerts(status, q):
        query = select(Alert)
        if status:
            query = query.where(Alert.status == status)
        if q and q.strip():
            needle = q.strip().casefold()
            query = query.where(or_(*(func.unicode_casefold(column).contains(needle, autoescape=True) for column in (Alert.event_type, Alert.source_ip, Alert.id))))
        return query

    def decode_cursor(value):
        try:
            stamp, alert_id = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
            at = datetime.fromisoformat(stamp)
            if at.tzinfo is None:
                raise ValueError()
            return as_utc(at), str(UUID(alert_id))
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
            raise HTTPException(422, "Некорректный курсор страницы") from exc

    @app.get("/api/health")
    def health(request: Request, db: Session = Depends(database)):
        db.execute(select(1))
        result = {"status": "ok", "auth_required": bool(settings.api_token), "write_auth_required": bool(settings.api_token)}
        if authenticated(request):
            configured = bool(settings.llm_api_key and settings.llm_model)
            result.update(llm_configured=configured, demo_auto_seed=settings.auto_seed_demo,
                          provider=runtime.diagnostics(configured))
        return result

    @app.get("/api/stats", response_model=StatsOut, dependencies=reads)
    def stats(db: Session = Depends(database)):
        recover_expired(db)
        statuses = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
        ranked = select(Analysis.severity, func.row_number().over(partition_by=Analysis.alert_id, order_by=[Analysis.created_at.desc(), Analysis.id.desc()]).label("position")).subquery()
        high_risk = db.scalar(select(func.count()).select_from(ranked).where(ranked.c.position == 1, ranked.c.severity.in_(["high", "critical"])))
        last = db.scalar(select(func.max(Alert.created_at)))
        received = db.scalar(select(func.count()).select_from(Alert).where(Alert.created_at >= utcnow() - timedelta(minutes=1)))
        return StatsOut(total=sum(statuses.values()), high_risk=high_risk, pending=sum(statuses.get(key, 0) for key in ("new", "processing", "error")),
                        analyses=db.scalar(select(func.count()).select_from(Analysis)), confirmed=statuses.get("confirmed", 0), false_positive=statuses.get("false_positive", 0),
                        received_last_minute=received, last_ingested_at=as_utc(last) if last else None)

    @app.post("/api/demo/seed", dependencies=writes)
    def load_demo(db: Session = Depends(database)):
        return {"created": seed(db)}

    @app.get("/api/history", response_model=list[HistoryEntry], dependencies=reads)
    def history(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(database)):
        rows = db.execute(select(Analysis, Alert).join(Alert, Analysis.alert_id == Alert.id).order_by(Analysis.created_at.desc(), Analysis.id.desc()).offset(offset).limit(limit)).all()
        decisions = {}
        if rows:
            for decision in db.scalars(select(AnalystDecision).where(AnalystDecision.analysis_id.in_([analysis.id for analysis, _ in rows])).order_by(AnalystDecision.created_at.desc())):
                decisions.setdefault(decision.analysis_id, []).append(decision_out(decision))
        return [HistoryEntry(analysis=analysis_out(analysis), event_type=redact(alert.event_type, secrets), source_ip=alert.source_ip,
                             current_status=alert.status, decisions=decisions.get(analysis.id, [])) for analysis, alert in rows]

    @app.get("/api/alerts", response_model=list[AlertOut], dependencies=reads)
    def alerts(status: str | None = Query(None, pattern=STATUS_PATTERN), q: str = Query("", max_length=120),
               limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0), db: Session = Depends(database)):
        recover_expired(db)
        rows = db.scalars(filtered_alerts(status, q).order_by(Alert.created_at.desc(), Alert.id.desc()).offset(offset).limit(limit)).all()
        return list_out(db, rows)

    @app.get("/api/alerts/page", response_model=AlertPage, dependencies=reads)
    def alert_page(status: str | None = Query(None, pattern=STATUS_PATTERN), q: str = Query("", max_length=120),
                   limit: int = Query(100, ge=1, le=500), cursor: str | None = Query(None, max_length=400), db: Session = Depends(database)):
        recover_expired(db)
        query = filtered_alerts(status, q)
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        if cursor:
            at, last_id = decode_cursor(cursor)
            query = query.where(or_(Alert.created_at < at, and_(Alert.created_at == at, Alert.id < last_id)))
        rows = list(db.scalars(query.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit + 1)))
        more, rows = len(rows) > limit, rows[:limit]
        next_cursor = None
        if more:
            payload = json.dumps([as_utc(rows[-1].created_at).isoformat(), rows[-1].id]).encode()
            next_cursor = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        return AlertPage(items=list_out(db, rows), total=total, next_cursor=next_cursor)

    @app.post("/api/alerts", response_model=AlertOut, dependencies=writes)
    def create_alert(payload: AlertCreate, db: Session = Depends(database)):
        alert = Alert(**clean(payload.model_dump()))
        db.add(alert)
        db.commit()
        return alert_out(alert)

    @app.get("/api/alerts/{alert_id}", response_model=AlertDetail, dependencies=reads)
    def detail(alert_id: UUID, db: Session = Depends(database)):
        recover_expired(db)
        alert = get_alert(db, alert_id)
        decisions = db.scalars(select(AnalystDecision).where(AnalystDecision.alert_id == alert.id).order_by(AnalystDecision.created_at.desc())).all()
        attempts = db.scalars(select(AnalysisAttempt).where(AnalysisAttempt.alert_id == alert.id).order_by(AnalysisAttempt.started_at.desc())).all()
        return AlertDetail(**alert_out(alert, latest(db, alert.id)).model_dump(),
                           rule_findings=evaluate_rules(redact(alert.raw_data, secrets), alert.source_ip, settings.trusted_networks),
                           decisions=[decision_out(row) for row in decisions], attempts=[attempt_out(row) for row in attempts])

    @app.get("/api/alerts/{alert_id}/analyses", response_model=list[AnalysisOut], dependencies=reads)
    def analyses(alert_id: UUID, db: Session = Depends(database)):
        get_alert(db, alert_id)
        return [analysis_out(row) for row in db.scalars(select(Analysis).where(Analysis.alert_id == str(alert_id)).order_by(Analysis.created_at.desc(), Analysis.id.desc()))]

    @app.get("/api/alerts/{alert_id}/attempts", response_model=list[AttemptOut], dependencies=reads)
    def attempts(alert_id: UUID, db: Session = Depends(database)):
        get_alert(db, alert_id)
        return [attempt_out(row) for row in db.scalars(select(AnalysisAttempt).where(AnalysisAttempt.alert_id == str(alert_id)).order_by(AnalysisAttempt.started_at.desc()))]

    def claim_analysis(alert_id, token):
        with sessions() as db:
            get_alert(db, alert_id)
            recover_expired(db)
            claimed = db.execute(update(Alert).where(Alert.id == alert_id, Alert.status != "processing")
                                 .values(status="processing", processing_token=token, processing_started_at=utcnow()))
            if claimed.rowcount != 1:
                db.rollback()
                raise HTTPException(409, "Анализ этого алерта уже выполняется")
            db.add(AnalysisAttempt(id=token, alert_id=alert_id, status="processing"))
            db.commit()
            alert = get_alert(db, alert_id)
            return {"raw_data": redact(alert.raw_data, secrets), "source_ip": alert.source_ip, "event_type": alert.event_type}

    def save_analysis(alert_id, token, service, findings):
        with sessions() as db:
            updated = db.execute(update(Alert).where(Alert.id == alert_id, Alert.processing_token == token)
                                 .values(status="analyzed", processing_token=None, processing_started_at=None))
            if updated.rowcount != 1:
                raise HTTPException(409, "Срок блокировки анализа истек. Обновите событие.")
            record = Analysis(alert_id=alert_id, **clean(service.result.model_dump()), false_positive_score=None,
                              analysis_mode=service.mode, model_name=redact(service.model_name, secrets) if service.model_name else None,
                              playbook_version=PLAYBOOK_VERSION, rule_findings=clean([rule.model_dump() for rule in findings]))
            db.add(record)
            db.flush()
            db.execute(update(AnalysisAttempt).where(AnalysisAttempt.id == token).values(status="succeeded", analysis_id=record.id,
                analysis_mode=service.mode, provider_error_code=service.provider_error_code, completed_at=utcnow()))
            db.commit()
            return analysis_out(record)

    def fail_analysis(alert_id, token, code):
        with sessions() as db:
            db.execute(update(Alert).where(Alert.id == alert_id, Alert.processing_token == token)
                       .values(status="error", processing_token=None, processing_started_at=None))
            db.execute(update(AnalysisAttempt).where(AnalysisAttempt.id == token, AnalysisAttempt.status == "processing")
                       .values(status="failed", error_code=code, completed_at=utcnow()))
            db.commit()

    @app.post("/api/alerts/{alert_id}/analyze", response_model=AnalysisOut, dependencies=writes)
    async def analyze(alert_id: UUID):
        alert_id, token = str(alert_id), str(uuid4())
        payload = await run_in_threadpool(claim_analysis, alert_id, token)
        completed, error_code = False, "analysis_failed"
        try:
            findings = evaluate_rules(payload["raw_data"], payload["source_ip"], settings.trusted_networks)
            service = await analyze_event(**payload, findings=findings, settings=settings, runtime=runtime)
            result = await run_in_threadpool(save_analysis, alert_id, token, service, findings)
            completed = True
            return result
        except InvalidLLMResponse as exc:
            error_code = exc.code
            raise HTTPException(503, ERROR_MESSAGES[exc.code], headers={"X-Analysis-Error": exc.code, "X-Request-ID": token}) from exc
        except asyncio.CancelledError:
            error_code = "cancelled"
            raise
        except SQLAlchemyError:
            error_code = "storage_error"
            raise
        finally:
            if not completed:
                await asyncio.shield(run_in_threadpool(fail_analysis, alert_id, token, error_code))

    @app.post("/api/alerts/{alert_id}/decision", response_model=DecisionOut, dependencies=writes)
    def decide(alert_id: UUID, payload: DecisionCreate, db: Session = Depends(database)):
        alert = get_alert(db, alert_id)
        analysis = latest(db, alert.id)
        if analysis is None or analysis.id != str(payload.analysis_id):
            raise HTTPException(409, "Решение можно принять только по последнему анализу. Обновите событие.")
        newest_id = select(Analysis.id).where(Analysis.alert_id == alert.id).order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(1).scalar_subquery()
        changed = db.execute(update(Alert).where(Alert.id == alert.id, Alert.status != "processing", newest_id == str(payload.analysis_id)).values(status=payload.decision))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, "Событие анализируется или появился новый анализ. Обновите данные.")
        decision = AnalystDecision(alert_id=alert.id, analysis_id=analysis.id, decision=payload.decision, comment=redact(payload.comment, secrets))
        db.add(decision)
        db.commit()
        return decision_out(decision)

    app.mount("/static", StaticFiles(directory=ROOT / "frontend"), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(ROOT / "frontend" / "index.html")

    return app


app = create_app()
