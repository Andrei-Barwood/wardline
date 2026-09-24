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
