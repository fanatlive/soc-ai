"""Small, explicit forward migrations; existing history and UUIDs are preserved."""
from sqlalchemy import func, insert, select, update

from .database import utcnow
from .models import Alert, Analysis, AnalysisAttempt, AnalystDecision, SchemaMigration
from .security import scrub_tree

SCHEMA_VERSION = 3


def migrate(engine, known_secrets=()):
    with engine.begin() as connection:
        SchemaMigration.__table__.create(connection, checkfirst=True)
        current = connection.scalar(select(func.max(SchemaMigration.version))) or 0
        if current > SCHEMA_VERSION:
            raise RuntimeError("Версия базы новее приложения. Используйте соответствующую версию сервера.")
        steps = [
            (1, "Baseline SOC AI Triage v2"),
            (2, "Persistent analysis attempts"),
            (3, "Structured redaction of existing records"),
        ]
        for version, description in steps:
            if version <= current:
                continue
            if version == 1:
                for model in (Alert, Analysis, AnalystDecision):
                    model.__table__.create(connection, checkfirst=True)
            elif version == 2:
                AnalysisAttempt.__table__.create(connection, checkfirst=True)
            elif version == 3:
                fields = {
                    Alert: ("raw_data", "event_type"),
                    Analysis: ("summary", "evidence", "recommended_actions", "limitations", "rule_findings", "model_name"),
                    AnalystDecision: ("comment",),
                }
                for model, names in fields.items():
                    table = model.__table__
                    for row in connection.execute(select(table.c.id, *(table.c[name] for name in names))).mappings():
                        original = {name: row[name] for name in names}
                        cleaned = scrub_tree(original, known_secrets)
                        changes = {name: cleaned[name] for name in names if cleaned[name] != original[name]}
                        if changes:
                            connection.execute(update(table).where(table.c.id == row["id"]).values(**changes))
            connection.execute(insert(SchemaMigration).values(version=version, description=description, applied_at=utcnow()))
