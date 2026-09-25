# Modelo de Amenazas

El presente documento analiza las amenazas operativas y de seguridad que Wardline gestiona. Este análisis se refiere de manera estricta y exclusiva al **proceso local** en su modo sandbox y **no debe utilizarse como guía o extrapolación para proteger otros sistemas reales**.

## Resumen de Amenazas

| Threat | Detection | Mitigation | Recovery |
| ------ | --------- | ---------- | -------- |
| Abuso de autenticación | `security_auth_failure` | Autenticación explícita por tokens | No aplica (se bloquea o rechaza sin estado persistente) |
| Abuso de autorización | `security_authz_denied` | `require_role` / Matrices de permisos | No aplica |
| Flooding de peticiones | `security_rate_limited` | Token Bucket Limiter (`rate_limit_requests_per_minute`) | El bucket se rellena solo; no hay estado que limpiar |
| Entrada mal formada | `validation_error` | Pydantic Schemas y parseo TCP estricto | Se descarta la entrada |
| Mensajes de tamaño excesivo | `message_too_large` | Lecturas limitadas (`tcp_max_message_bytes`, `http_max_body_bytes`) | Desconexión inmediata (TCP EOF) o descarte (UDP/HTTP) |
| Agotamiento de conexiones TCP | `connection_limit` | Control de pool (`tcp_max_connections`) y Timeouts | Liberación en cascada cuando expiran los timeouts |
| Ráfagas UDP | `security_quota_exceeded` | Límite de ráfagas sin respuesta (`udp_packets_per_second`) | El bucket se rellena solo |
| Inundación de logs | `security_log_volume` | Auditoría restringida a volúmenes y redacción | Rotación y limpieza programada de volúmenes de eventos |
| Agotamiento de recursos del proceso | `security_circuit_open` | Circuit Breaker (`circuit_failure_threshold`) | Degradación temporal; el circuito cierra solo al recuperarse |

## Abuso de autenticación

**Threat**: Consumo de recursos computacionales intentando adivinar llaves o acceder sin identificarse. Se presiona el módulo de identidad y la CPU por validación criptográfica constante (o en nuestro caso local, strings estáticos).

**Attack surface**: Cabecera HTTP `Authorization` y el campo `token` en payloads TCP/UDP en rutas no públicas.

**Impact**: Sin control, el proceso despilfarraría tiempo computando estados inauténticos o filtraría datos. Con el control activo, los requests son ignorados o desconectados instantáneamente.

**Detection**: `security_auth_failure`

**Mitigation**: Restricción inmediata que rechaza con 401.

**Recovery**: La amenaza no abre incidente (es un rechazo natural, de severidad baja). No hay estado que limpiar.

## Abuso de autorización

**Threat**: Usuarios de bajos privilegios escalando para ejecutar rutinas operacionales. Presiona la integridad del modelo de configuración y las transiciones del simulador o de incidentes.

**Attack surface**: Rutas HTTP como `/admin/config` o `/incidents/{id}/contain` llamadas con tokens del rol Viewer.

**Impact**: Sin control, un observador alteraría los rate limits o aislaría clientes. Con el control, recibe 403 y la acción se descarta sin evaluar la lógica subyacente.

**Detection**: `security_authz_denied`

**Mitigation**: Dependencias de `require_role` evaluadas antes del route core.

**Recovery**: La amenaza no abre incidente porque su severidad es baja y la acción simplemente se desecha.

## Flooding de peticiones

**Threat**: Sobrecarga de eventos procesables que ahogan los canales de servicio y bloquean el reactor asyncio.

**Attack surface**: Rutas públicas y autenticadas HTTP, y datagramas masivos UDP o tráfico TCP constante.

**Impact**: Sin control, la aplicación tardaría en responder o fallaría el Health Gate interno. Con el control, el atacante agota su propio cubo de fichas y recibe rechazos inmediatos (429 HTTP o caídas de TCP/UDP silentes).

**Detection**: `security_rate_limited` y eventos de anomalía derivados como `anomaly_rate_abuse` o los sintéticos `simulated_rate_abuse` (via `simulate_burst`).

**Mitigation**: Implementado en memoria mediante Token Bucket con la configuración de `rate_limit_requests_per_minute` y `rate_limit_burst`.

**Recovery**: El bucket se rellena solo; no hay estado que limpiar.

## Entrada mal formada

**Threat**: Inyección de campos inválidos o datos que la lógica de parseo no soporta, estresando los diccionarios de tipos.

**Attack surface**: Cuerpos JSON de peticiones POST HTTP, líneas serializadas por TCP y datagramas JSON sobre UDP.

**Impact**: Sin control, generaría excepciones de Python que se fugarían en 500s volcando memoria de stack trace. Con el control, las excepciones caen dócilmente en manejadores devolviendo 400.

**Detection**: `validation_error` (para HTTP) e `invalid_message` (para conectores binarios tcp/udp).

**Mitigation**: Esquemas restrictivos con `extra="forbid"` de Pydantic y parseo JSON transaccional.

**Recovery**: La amenaza no abre incidente y se gestiona como ruido ambiental; el estado se mantiene íntegro.

## Mensajes de tamaño excesivo

**Threat**: Transferencia de grandes volúmenes de texto o binario dentro de un payload válido en busca de OOM (Out of Memory).

**Attack surface**: Lector de líneas TCP, tamaño del body en requests HTTP y tramas de recepción en datagramas UDP.

**Impact**: Sin control, la carga ocuparía toda la RAM del proceso asignada al buffer asyncio. Con el control, el servicio aborta el streaming y expulsa al socket en cuanto cruza el byte threshold.

**Detection**: `message_too_large`

**Mitigation**: Restricción de buffer configurada en `tcp_max_message_bytes`, `http_max_body_bytes` y `udp_max_datagram_bytes`.

**Recovery**: Desconexión pura; no hay incidentes abiertos. Se reinicia el stream.

## Agotamiento de conexiones TCP

**Threat**: Mantenimiento de miles de sockets abiertos concurrentemente que no se cierran (similar a un ataque slowloris en capa 4).

**Attack surface**: Sockets pasivos de escucha en el puerto 9001 (TCP).

**Impact**: Sin control, el descriptor máximo de archivos locales del proceso se agotaría, previniendo nuevos accesos legítimos. Con el control, los nuevos sockets son cerrados con EOF inmediatamente al detectar pool lleno.

**Detection**: `connection_limit` y la anomalía consolidada `anomaly_connection_pressure` (emulable con `simulate_connection_pressure`).

**Mitigation**: Pool limitado bajo `tcp_max_connections` y expiración forzosa configurada por `tcp_idle_timeout_seconds`.

**Recovery**: Apertura de incidentes si se acumulan anomalías de presión; un operador puede decidir aislar el `client_id` (vía `contain`) y limpiar bloqueos mediante su propio proceso de mitigación.

## Ráfagas UDP

**Threat**: Ahogamiento de ancho de banda enviando paquetes ciegos que obligan al servidor a emitir colisiones de respuestas ACK sobre UDP sin estado.

**Attack surface**: Recepción del socket no-orientado a conexión en el puerto UDP 9002.

**Impact**: Sin control, las ráfagas harían que nuestro puerto dedicase ciclos respondiendo. Con el control, tras agotar la cuota, los datagramas se dropean sin generar tráfico de salida adicional.

**Detection**: `security_quota_exceeded` (y opcionalmente `datagrams_dropped` en métricas, o simulado con `simulate_udp_burst`).

**Mitigation**: Cuotas por cliente configuradas bajo `udp_packets_per_second` (o el límite fijo de ráfagas).

**Recovery**: El bucket se rellena solo; no hay estado que limpiar.

## Inundación de logs

**Threat**: Un atacante logra que las denegaciones formen líneas de eventos masivas ahogando el pipeline o el disco persistente de auditoría.

**Attack surface**: Cualquier evento que el sistema se vea obligado a parsear y escupir (errores, límites de tasa repetitivos, o autenticaciones fallidas).

**Impact**: Sin control, el archivo .jsonl y la BD SQLite crecerían infinitamente, bloqueando i/o. Con el control, la lógica unifica eventos o colapsa descripciones limitando campos en el log.

**Detection**: `security_log_volume` (y la subsecuente anomalía).

**Mitigation**: Muestreo pasivo de anomalías y agregación lógica que previene escribir por encima de cuotas de IO.

**Recovery**: Si un operador detecta este incidente, debe evaluar si requiere el uso de rollback del estado configurado en `admin/config` o aislar al atacante.

## Agotamiento de recursos del proceso

**Threat**: Errores catastróficos por caídas subyacentes o saturación asíncrona (recursos limitados que la app en su interior depende).

**Attack surface**: Todas las capas de la aplicación simultáneamente o dependencias críticas de persistencia / loop principal.

**Impact**: Sin control, cada request experimentaría latencias desastrosas. Con el control, el servicio corta el hilo devolviendo error fall-fast preservando una mínima vitalidad de `/health`.

**Detection**: `security_circuit_open` y fallos englobados de circuito.

**Mitigation**: Configuración por medio de `circuit_failure_threshold` abriendo el cortacircuitos por `circuit_open_seconds`.

**Recovery**: La degradación es temporal; el circuito evalúa intermitentemente y el circuito cierra solo al recuperarse los servicios subyacentes.

## Principios Defensivos Integrados

* **least privilege**: Implementado a lo largo del sistema y jerarquía de roles, requiriendo un router autenticado por defecto para impedir fugas por omisión.
* **defense in depth**: La protección no es única; primero se comprueba el esquema estricto (Pydantic), luego autenticación (identidad) y luego límite de carga y cuotas en niveles subsecuentes.
* **secure defaults**: Se requiere el uso y bind al loopback, las documentaciones de OpenAPI `/docs` están desactivadas explícitamente, y `/health` es pública pero purgada de secretos y métricas sensibles.
* **fail safely**: Si los límites están mal configurados o la carga causa caídas, las herramientas como anomalías deciden caer negando accesos en lugar de abrirlos, operando un estricto cierre ante fallos.
* **input validation**: Uso exhaustivo de esquemas con comprobación de límites numéricos, de regex y profundidad máxima, rechazando basuras activamente.
* **explicit authorization**: Todo endpoint restrictivo aplica `require_role` garantizando el mapeo inamovible de permisos a la acción concreta en tiempo de inyección de dependencias.
* **observability**: La salud, eventos analíticos estandarizados en SQLite y métricas agregadas que proporcionan instrumentación y telemetría purificada sin filtrar logs de error nativos (solo resúmenes).
* **auditability**: Archivos y tablas generados pasivamente de forma persistente (`.jsonl redactado` y tablas de incidents) donde no quedan llaves y las resoluciones son inmutables.
* **graceful degradation**: Usando el estado `circuit_open` limitamos respuestas costosas para que los recursos asíncronos y el endpoint base `/health` siga vivo.
* **recovery**: El modelo no termina en el colapso; la máquina de estados de los incidentes y el mecanismo de mitigación posibilitan un rollback de la lista blanca bajo control administrativo.

## Simulación Legítima

La forma legítima e instruccional de observar estas señales defensivas sin generar tráfico real malicioso es utilizar el simulador interno. El modo de operación por defecto del simulador es `inprocess`, lo que evita envíos por la pila de red del sistema operativo. Los escenarios autorizados para ver los eventos listados son `simulate_burst`, `simulate_invalid_messages`, `simulate_connection_pressure` y `simulate_udp_burst`.
