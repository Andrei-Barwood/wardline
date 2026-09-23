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



