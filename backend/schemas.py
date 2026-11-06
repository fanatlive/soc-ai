from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["new", "processing", "analyzed", "confirmed", "false_positive", "error"]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=600)]


class AlertCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = Field(max_length=45)
    event_type: str = Field(min_length=1, max_length=80)
    raw_data: str = Field(min_length=1, max_length=2000)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value.strip()))

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp должен содержать часовой пояс")
        try:
            return value.astimezone(timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise ValueError("timestamp выходит за поддерживаемый диапазон UTC") from exc

    @field_validator("raw_data", "event_type")
    @classmethod
    def not_blank(cls, value):
        if not value.strip() or "\x00" in value:
            raise ValueError("Поле не должно быть пустым или содержать NUL")
        return value.strip()


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    description: ShortText
    source: Annotated[str, StringConstraints(min_length=1, max_length=150)]
    quote: ShortText | None = None


class RuleFinding(BaseModel):
    id: str
    description: str
    kind: Literal["indicator", "context"]
    evidence: list[Evidence]
    facts: dict = Field(default_factory=dict)


class LLMResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    severity: Severity
    summary: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    evidence: list[Evidence] = Field(max_length=30)
    recommended_actions: list[ShortText] = Field(min_length=1, max_length=12)
    confidence: float | None = Field(ge=0, le=1, allow_inf_nan=False)
    limitations: list[ShortText] = Field(min_length=1, max_length=15)


class AnalysisOut(LLMResult):
    id: str
    alert_id: str
    false_positive_score: float | None
    analysis_mode: Literal["llm", "hybrid", "rules_only"]
    model_name: str | None
    playbook_version: str
    rule_findings: list[RuleFinding]
    created_at: datetime


class DecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: UUID
    decision: Literal["confirmed", "false_positive"]
    comment: str = Field(default="", max_length=1000)


class DecisionOut(BaseModel):
    id: str
    alert_id: str
    analysis_id: str
    decision: Literal["confirmed", "false_positive"]
    comment: str
    created_at: datetime


class AlertOut(BaseModel):
    id: str
    timestamp: datetime
    source_ip: str
    event_type: str
    raw_data: str
    status: Status
    created_at: datetime
    latest_analysis: AnalysisOut | None = None


class AlertDetail(AlertOut):
    rule_findings: list[RuleFinding]
    decisions: list[DecisionOut]
    attempts: list["AttemptOut"] = Field(default_factory=list)


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    next_cursor: str | None


class AttemptOut(BaseModel):
    id: str
    alert_id: str
    analysis_id: str | None
    status: Literal["processing", "succeeded", "failed", "abandoned"]
    analysis_mode: str | None
    error_code: str | None
    provider_error_code: str | None
    started_at: datetime
    completed_at: datetime | None


class StatsOut(BaseModel):
    total: int
    high_risk: int
    pending: int
    analyses: int
    confirmed: int
    false_positive: int
    received_last_minute: int = 0
    last_ingested_at: datetime | None = None


class HistoryEntry(BaseModel):
    analysis: AnalysisOut
    event_type: str
    source_ip: str
    current_status: Status
    decisions: list[DecisionOut]
