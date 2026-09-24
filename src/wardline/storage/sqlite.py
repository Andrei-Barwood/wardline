import json
import os
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    Engine,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    delete,
    insert,
    select,
    update,
)

from wardline.contracts import (
    SEVERITY_RANK,
    ErrorCode,
    IncidentState,
    SecurityEvent,
    ServiceName,
    Severity,
)
from wardline.errors import WardlineError
from wardline.incidents.models import Incident, IncidentAction

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

incidents = Table(
    "incidents",
    metadata,
    Column("id", String, primary_key=True),
    Column("state", String, nullable=False),
    Column("title", String, nullable=False),
    Column("source", String, nullable=False),
    Column("service", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("correlation_id", String, nullable=False),
    Column("simulation", Boolean, nullable=False),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

incident_actions = Table(
    "incident_actions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String, ForeignKey("incidents.id"), nullable=False),
    Column("at", String, nullable=False),
    Column("actor", String, nullable=False),
    Column("action", String, nullable=False),
    Column("from_state", String, nullable=False),
    Column("to_state", String, nullable=False),
    Column("detail", Text, nullable=False),
    Index("idx_incident_actions_inc_id", "incident_id"),
)


def _init_sqlite_engine(db_path: str) -> Engine:
    if db_path.startswith("sqlite:///"):
        path = db_path[10:]
    elif db_path.startswith("sqlite://"):
        path = db_path[9:]
    else:
        path = db_path

    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    url = f"sqlite:///{path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    with engine.connect() as conn:
        metadata.create_all(engine)
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
    return engine


class SqliteEventRepository:
    def __init__(self, db_path: str) -> None:
        self.engine = _init_sqlite_engine(db_path)

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


class SqliteIncidentRepository:
    """SQLite-backed Incident repository storing incidents and incident_actions."""

    def __init__(self, db_path: str) -> None:
        self.engine = _init_sqlite_engine(db_path)
        self._identity_cache: dict[str, Incident] = {}

    def add(self, incident: Incident) -> None:
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(incidents.c.id).where(incidents.c.id == incident.id)
            ).first()
            if existing is not None:
                raise WardlineError(ErrorCode.validation_error, "incident already exists")

            conn.execute(
                insert(incidents).values(
                    id=incident.id,
                    state=incident.state.value,
                    title=incident.title,
                    source=incident.source,
                    service=incident.service.value,
                    severity=incident.severity.value,
                    correlation_id=incident.correlation_id,
                    simulation=incident.simulation,
                    created_at=incident.created_at.isoformat(),
                    updated_at=incident.updated_at.isoformat(),
                )
            )
            for action in incident.actions:
                conn.execute(
                    insert(incident_actions).values(
                        incident_id=incident.id,
                        at=action.at.isoformat(),
                        actor=action.actor,
                        action=action.action,
                        from_state=action.from_state.value,
                        to_state=action.to_state.value,
                        detail=action.detail,
                    )
                )
        self._identity_cache[incident.id] = incident

    def save(self, incident: Incident) -> None:
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(incidents.c.id).where(incidents.c.id == incident.id)
            ).first()
            if existing is None:
                raise WardlineError(ErrorCode.not_found, "incident not found")

            conn.execute(
                update(incidents)
                .where(incidents.c.id == incident.id)
                .values(
                    state=incident.state.value,
                    title=incident.title,
                    source=incident.source,
                    service=incident.service.value,
                    severity=incident.severity.value,
                    correlation_id=incident.correlation_id,
                    simulation=incident.simulation,
                    updated_at=incident.updated_at.isoformat(),
                )
            )
            conn.execute(
                delete(incident_actions).where(incident_actions.c.incident_id == incident.id)
            )
            for action in incident.actions:
                conn.execute(
                    insert(incident_actions).values(
                        incident_id=incident.id,
                        at=action.at.isoformat(),
                        actor=action.actor,
                        action=action.action,
                        from_state=action.from_state.value,
                        to_state=action.to_state.value,
                        detail=action.detail,
                    )
                )
        self._identity_cache[incident.id] = incident

    def get(self, incident_id: str) -> Incident | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(incidents).where(incidents.c.id == incident_id)).first()
            if row is None:
                return None
            action_rows = conn.execute(
                select(incident_actions)
                .where(incident_actions.c.incident_id == incident_id)
                .order_by(incident_actions.c.id)
            ).fetchall()

            actions = tuple(
                IncidentAction(
                    at=datetime.fromisoformat(ar.at),
                    actor=ar.actor,
                    action=ar.action,
                    from_state=IncidentState(ar.from_state),
                    to_state=IncidentState(ar.to_state),
                    detail=ar.detail,
                )
                for ar in action_rows
            )

            reconstructed = Incident(
                id=row.id,
                state=IncidentState(row.state),
                title=row.title,
                source=row.source,
                service=ServiceName(row.service),
                severity=Severity(row.severity),
                correlation_id=row.correlation_id,
                simulation=bool(row.simulation),
                created_at=datetime.fromisoformat(row.created_at),
                updated_at=datetime.fromisoformat(row.updated_at),
                actions=actions,
            )
            cached = self._identity_cache.get(incident_id)
            if cached == reconstructed:
                return cached
            self._identity_cache[incident_id] = reconstructed
            return reconstructed

    def list_all(self) -> list[Incident]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(incidents).order_by(incidents.c.created_at, incidents.c.id)
            ).fetchall()
            if not rows:
                return []
            result: list[Incident] = []
            for row in rows:
                action_rows = conn.execute(
                    select(incident_actions)
                    .where(incident_actions.c.incident_id == row.id)
                    .order_by(incident_actions.c.id)
                ).fetchall()
                actions = tuple(
                    IncidentAction(
                        at=datetime.fromisoformat(ar.at),
                        actor=ar.actor,
                        action=ar.action,
                        from_state=IncidentState(ar.from_state),
                        to_state=IncidentState(ar.to_state),
                        detail=ar.detail,
                    )
                    for ar in action_rows
                )
                reconstructed = Incident(
                    id=row.id,
                    state=IncidentState(row.state),
                    title=row.title,
                    source=row.source,
                    service=ServiceName(row.service),
                    severity=Severity(row.severity),
                    correlation_id=row.correlation_id,
                    simulation=bool(row.simulation),
                    created_at=datetime.fromisoformat(row.created_at),
                    updated_at=datetime.fromisoformat(row.updated_at),
                    actions=actions,
                )
                cached = self._identity_cache.get(row.id)
                if cached == reconstructed:
                    result.append(cached)
                else:
                    self._identity_cache[row.id] = reconstructed
                    result.append(reconstructed)
            return result

    def close(self) -> None:
        self.engine.dispose()
