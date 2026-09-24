import json
import os

from sqlalchemy import (
    Boolean,
    Column,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    insert,
    select,
)

from wardline.contracts import SEVERITY_RANK, SecurityEvent, ServiceName, Severity

metadata = MetaData()

security_events = Table(
    "security_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", String, nullable=False),
    Column("source", String, nullable=False),
    Column("service", String, nullable=False),
    Column("event_type", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("simulation", Boolean, nullable=False),
    Column("action", String, nullable=False),
    Column("correlation_id", String, nullable=False),
    Column("details", Text, nullable=False),
    Index("idx_security_events_ts", "timestamp"),
)


class SqliteEventRepository:
    def __init__(self, db_path: str) -> None:
        if db_path.startswith("sqlite:///"):
            path = db_path[10:]
        elif db_path.startswith("sqlite://"):
            path = db_path[9:]
        else:
            path = db_path

        dir_name = os.path.dirname(path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        # SQLite URL for sqlalchemy
        url = f"sqlite:///{path}"
        self.engine = create_engine(url, connect_args={"check_same_thread": False})

        with self.engine.connect() as conn:
            metadata.create_all(self.engine)
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")

    def add(self, event: SecurityEvent) -> None:
        with self.engine.begin() as conn:
            stmt = insert(security_events).values(
                timestamp=event.timestamp.isoformat(),
                source=event.source,
                service=event.service.value,
                event_type=event.event_type,
                severity=event.severity.value,
                simulation=event.simulation,
                action=event.action,
                correlation_id=event.correlation_id,
                details=json.dumps(event.details),
            )
            conn.execute(stmt)

    def list_events(
        self,
        *,
        limit: int = 100,
        min_severity: Severity | None = None,
        service: ServiceName | None = None,
        simulation: bool | None = None,
    ) -> list[SecurityEvent]:
        bounded = min(5001, max(1, limit))

        stmt = select(security_events)
        if service is not None:
            stmt = stmt.where(security_events.c.service == service.value)
        if simulation is not None:
            stmt = stmt.where(security_events.c.simulation == simulation)

        stmt = stmt.order_by(security_events.c.timestamp.desc(), security_events.c.id.desc())

        matched = []
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            for row in result:
                evt_sev = Severity(row.severity)
                if (
                    min_severity is not None
                    and SEVERITY_RANK[evt_sev] < SEVERITY_RANK[min_severity]
                ):
                    continue

                matched.append(
                    SecurityEvent(
                        timestamp=row.timestamp,
                        source=row.source,
                        service=ServiceName(row.service),
                        event_type=row.event_type,
                        severity=evt_sev,
                        simulation=bool(row.simulation),
                        action=row.action,
                        correlation_id=row.correlation_id,
                        details=json.loads(row.details),
                    )
                )
                if len(matched) >= bounded:
                    break

        return matched

    def close(self) -> None:
        self.engine.dispose()
