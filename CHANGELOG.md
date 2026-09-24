# Changelog

El formato sigue Keep a Changelog.

## [0.1.0] - 2026-09-23

### Added

- Esqueleto del capítulo 1.
- Configuración del laboratorio mediante entorno y config/default.toml.
- API HTTP local con /health, /version y /status.
- Servicio TCP local con protocolo de líneas JSON y límites de sesión.
- Servicio UDP local sin amplificación: los datagramas grandes no reciben respuesta.
- Logging estructurado en formato JSON y registro de auditoría append-only con redacción y coalescencia.
- Autenticación mediante claves de API de laboratorio con comparación en tiempo constante y protección de /status, TCP y UDP.
- Jerarquía de roles (viewer, operator, admin) y autorización con fallo cerrado para rutas HTTP y comandos TCP.




### PROMPT 09 — Validación
* **Validation module**: Created `src/wardline/security/validation.py` to enforce strict schema constraints.
* **TCP & UDP Schemas**: Added logic to `validate_tcp` and `validate_udp` leveraging new frozen dataclasses `TcpCommand` and `UdpCommand`.
* **Protocol parsers**: Refactored `src/wardline/tcp/protocol.py` and `src/wardline/udp/protocol.py` to delegate to validation.
* **Testing updates**: Created unit tests in `tests/unit/test_validation.py` and `tests/security/test_malformed_input.py`.

### PROMPT 10 — Rate limiting
* **TokenBucketLimiter**: Replaced InMemoryRateLimiter with a real token bucket implementation using an injectable clock.
* **HTTP**: Added `check_rate_limit` FastAPI dependency enforcing limits on both public and authenticated routes. Returns 429 and `Retry-After` header when limit exceeded.
* **TCP & UDP**: Integrated limits checking into session creation and datagram parsing, accurately tracking consumed quotas and bypassing UDP responses when budget is exhausted.

### PROMPT 15 — Monitorización
* **Alert filtering**: Implemented `select_alerts` in `src/wardline/monitoring/alerts.py` to filter security and anomaly events with severity thresholds.
* **Monitoring endpoints**: Added `GET /metrics`, `GET /alerts`, and `GET /security/summary` exposing system metrics, alerts, and security overview to viewers and operators.
* **Active blocks**: Exposed `count_active(now)` on `BlockRegistry` and `InMemoryBlockRegistry`.
* **Testing**: Added unit and integration tests in `tests/unit/test_metrics_shape.py`, `tests/unit/test_alerts_selection.py`, and `tests/integration/test_monitoring_api.py`.

### PROMPT 16 — Gestión de incidentes
* **Incident state machine**: Implemented `transition` in `src/wardline/incidents/machine.py` enforcing immutable state progressions (`DETECTED` -> `INVESTIGATING` -> `CONTAINED` -> `RECOVERING` -> `RESOLVED`).
* **Incident persistence**: Extended `src/wardline/storage/sqlite.py` with `incidents` and `incident_actions` tables and `SqliteIncidentRepository`.
* **Logical client blocking**: Implemented in-memory process-scoped client blocking in `src/wardline/clients/blocks.py`, enforced across HTTP, TCP, and UDP traffic.
* **Incident & Admin API**: Added `GET /incidents`, `GET /incidents/{id}`, `POST /incidents/{id}/acknowledge`, `POST /incidents/{id}/contain`, `POST /incidents/{id}/resolve`, and `POST /admin/clients/{client_id}/unblock`.
* **Testing**: Added tests in `tests/unit/test_incident_machine.py`, `tests/integration/test_incident_routes.py`, and `tests/security/test_incident_authorization.py`.

### PROMPT 17 — Sistema de recuperación
* **Health Recovery Gate**: Implemented `LocalHealthGate` in `src/wardline/incidents/recovery.py` with real local socket probes for TCP and UDP, in-process loopback deadlock-free HTTP checking via `HealthRegistry`, and strict loopback host restrictions.
* **Selective Incident Unblock**: Extended `BlockRegistry` with `unblock_incident(client_id, incident_id)` to selectively remove incident-specific blocks while maintaining blocks tied to other incidents.
* **Incident Resolution Flow**: Coordinated `IncidentService.resolve` with `LocalHealthGate`. Moving from `CONTAINED` transitions to `RECOVERING`, and transitions to `RESOLVED` with selective unblocking if health checks pass. Retries from `RECOVERING` with failing health return 409 `invalid_state_transition` with `details.health`.
* **Operational Config Whitelist & Rollback**: Added whitelist validation for operational parameters, `GET /admin/config`, `POST /admin/config`, `POST /admin/recovery/rollback`, and `POST /admin/clients/{id}/block`. Rollback and patches immediately reflect on rate limiters and runtime components.
* **Safe Reset Utility**: Implemented `safe_reset(data_dir: Path)` in `src/wardline/storage/cleanup.py` and `scripts/reset.sh` to safely purge local databases and `.jsonl` data files while strictly rejecting paths outside `data/`.
* **Testing**: Added test suites in `tests/unit/test_config_rollback.py`, `tests/integration/test_recovery_flow.py`, and `tests/security/test_rollback_whitelist.py`.

### PROMPT 18 — Sistema de misiones
* **Mission Catalog and Models**: Defined `Mission` and `MissionResult` frozen dataclasses in `src/wardline/missions/models.py`. Implemented 5 educational missions (`m01`..`m05`) covering availability, identity, rate limiting, observability, and recovery in `src/wardline/missions/catalog.py` with strict absence of forbidden offensive jargon.
* **Automated Mission Checks**: Implemented `check_m01`..`check_m05` in `src/wardline/missions/checks.py` exercising real service health and logging probes, authentication and authorization boundaries, burst token bucket enforcement, connection pressure observability, and complete incident resolution cycles.
* **Safe Mission Runner**: Implemented `run_check` in `src/wardline/missions/runner.py` capturing unexpected exceptions to return failing `MissionResult` without raising 500 or exposing traces.
* **Mission API**: Exposed `GET /missions`, `GET /missions/{id}`, and `POST /missions/{id}/check` requiring viewer for read operations and operator for check executions.
* **Mission Documentation**: Documented all five missions, objectives, concepts, required actions, execution guides, and conceptual explanations in `docs/missions.md`.
* **Testing**: Added unit and integration tests in `tests/unit/test_mission_catalog.py` and `tests/integration/test_mission_checks.py`.

### PROMPT 19 — Tests unitarios
* **Defensive Edge Case Unit Tests**: Added `tests/unit/test_defensive_edge_cases.py` covering boundary conditions: complete `SEVERITY_RANK` mapping and ties, `redact` preserving ints and nested traversal, token bucket cost above balance without negative values, quota rejection without count increments, sliding-window circuit breaker isolation, extra field dropping in `validate_tcp`, duplicate role parsing rejection in API keys, immutability on illegal incident transitions, `assert_loopback` strict octet verification (rejecting `127.0.0.2`), `select_alerts` with empty input, and path traversal escape prevention in `safe_reset`.
* **Hardened Path Reset**: Reinforced `safe_reset(data_dir: Path, *, allowed_root: Path) -> list[Path]` requiring path resolution, target basename `data`, and strict encapsulation within `allowed_root`.
* **Automatic Test Markers**: Configured `pytest_collection_modifyitems` in `tests/conftest.py` to automatically assign `unit`, `integration`, and `security` markers based on test paths without manual markers.
* **Coverage Analysis & Gap Audit**: Generated code coverage audit across the suite reaching 84% total coverage (>90% on core decision logic) and documented uncovered entrypoints in `docs/test-gaps.md`.

### PROMPT 20 — Tests de integración
* **Live Stack Fixture**: Implemented `Stack` dataclass and `stack` async fixture in `tests/integration/conftest.py` binding HTTP, TCP, and UDP on loopback (`127.0.0.1`) with ephemeral ports (`0`), isolated SQLite storage in `tmp_path`, and automated resource disposal.
* **Network Testing Helpers**: Added `open_tcp`, `send_tcp_line`, `read_tcp_line`, and `roundtrip_udp` with asyncio sockets in `tests/integration/conftest.py`.
* **Chapter Scenarios**:
  - `tests/integration/test_stack_chapter1.py`: Verified `GET /version`, `GET /health`, TCP ping-pong, UDP beacon-ack, and structured correlation ID logging.
  - `tests/integration/test_stack_chapter2.py`: Validated role-based boundaries on live HTTP endpoints (anonymous 401, viewer 200/403, operator 200 simulation run, admin 200 config access, operator 403 config edit).
  - `tests/integration/test_stack_chapter3.py`: Enforced burst rate limits (429 on third request), TCP oversized line connection drops with EOF, and silent drop on oversized UDP datagrams without replies.
  - `tests/integration/test_stack_chapter4.py`: Verified four in-process simulation runs, presence of synthetic event types in `GET /events`, security summary metrics, and medium-severity alert queries.
  - `tests/integration/test_stack_chapter5.py`: Executed complete incident lifecycle (connection pressure anomaly detection -> acknowledge -> contain with client block -> resolve with selective unblock -> post-resolution TCP ping).
* **Database Persistence Across Restarts**: Implemented `tests/integration/test_sqlite_restart_keeps_events.py` verifying that events and incidents survive complete stack shutdowns and are queryable in subsequent instances.




