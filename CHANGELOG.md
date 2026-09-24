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


