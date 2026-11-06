from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base, utcnow


def new_id() -> str:
    return str(uuid4())


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("status IN ('new','processing','analyzed','confirmed','false_positive','error')"),
        Index("ix_alerts_created", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str] = mapped_column(String(45))
    event_type: Mapped[str] = mapped_column(String(80))
    raw_data: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="new")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # A DB-backed lease prevents duplicate analysis across threads and workers.
    processing_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processing_token: Mapped[str | None] = mapped_column(String(36), nullable=True)


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint("severity IN ('low','medium','high','critical')"),
        CheckConstraint("analysis_mode IN ('llm','hybrid','rules_only')"),
        Index("ix_analyses_alert_created", "alert_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    severity: Mapped[str] = mapped_column(String(10))
    false_positive_score: Mapped[float | None] = mapped_column(nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON)
    recommended_actions: Mapped[list] = mapped_column(JSON)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    limitations: Mapped[list] = mapped_column(JSON)
    analysis_mode: Mapped[str] = mapped_column(String(15))
    model_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    playbook_version: Mapped[str] = mapped_column(String(30))
    rule_findings: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalystDecision(Base):
    __tablename__ = "analyst_decisions"
    __table_args__ = (CheckConstraint("decision IN ('confirmed','false_positive')"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    decision: Mapped[str] = mapped_column(String(20))
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisAttempt(Base):
    __tablename__ = "analysis_attempts"
    __table_args__ = (
        CheckConstraint("status IN ('processing','succeeded','failed','abandoned')"),
        Index("ix_attempts_alert_started", "alert_id", "started_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    analysis_id: Mapped[str | None] = mapped_column(ForeignKey("analyses.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    analysis_mode: Mapped[str | None] = mapped_column(String(15), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    provider_error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    version: Mapped[int] = mapped_column(primary_key=True)
    description: Mapped[str] = mapped_column(String(150))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
