# Arquitectura de Wardline

El análisis defensivo y los controles mitigadores de esta arquitectura se encuentran detallados en el [Modelo de Amenazas](threat-model.md).

El propósito del laboratorio Wardline es proveer un entorno educativo controlado y blindado localmente donde se puedan analizar patrones de red, evaluar contramedidas (rate limits, circuit breakers) y simular la respuesta a incidentes a través de una API HTTP y servicios de red (TCP/UDP), sin riesgo de exposición a redes externas o uso ofensivo.

## Contrato de Red y Servicios
```text
           +-------------+
           |   Cliente   |
           +------+------+
                  |
    +-------------+-------------+
    |             |             |
+---v---+     +---v---+     +---v---+
|  API  |     |  TCP  |     |  UDP  |
| HTTP  |     | Server|     | Server|
+---+---+     +---+---+     +---+---+
    |             |             |
    +-------+-----+-------------+
            |
    +-------v-------+
    |  Core Lógico  |
    |  (Controles,  |
    |   Métricas)   |
    +-------+-------+
            |
    +-------v-------+
    |  Almacenaje   |
    |   (SQLite)    |
    +---------------+
```

## Tabla de Procesos y Puertos por Defecto

Todos los servicios vinculan sus interfaces por defecto y de manera restrictiva a direcciones loopback (`127.0.0.1`, `localhost`, `::1`).
| Servicio  | Protocolo | Dirección    | Puerto |
| --------- | --------- | ------------ | ------ |
| API HTTP  | HTTP      | `127.0.0.1`  | `8080` |
| Servidor  | TCP       | `127.0.0.1`  | `9001` |
| Servidor  | UDP       | `127.0.0.1`  | `9002` |

## Ubicación de las Decisiones de Control

* **Validación**: Ocurre en la carga de variables (`settings.py`), donde las interfaces de red fuera de loopback son rechazadas (con la excepción de Docker y la bandera estricta de `WARDLINE_CONTAINER=1`). En los conectores HTTP, Pydantic y las dependencias de FastAPI (en `deps.py`) se encargan de validar la forma de las peticiones y las dimensiones del cuerpo.
* **Autenticación y Autorización (Auth)**: Administrado vía llaves maestras para la API a través de `ApiKeyAuthProvider` configuradas por la variable `WARDLINE_DEV_API_KEYS`. Dependencias especializadas en HTTP (`require_role`) controlan qué usuario y rol pueden interactuar con las rutas.
* **Límites de Uso y Quotas**: Enforzados a través de un esquema de `TokenBucketLimiter` (`rate_limit.py`) que aplica penalizaciones antes del procesamiento del core de negocio. Las Quotas de red protegen los puertos de exhaustión.
* **Aislamiento lógico de incidentes**: Las contramedidas (`blocks`) para clientes abusivos no interactúan con IPtables ni APIs de host; ocurren lógicamente en el sistema (`InMemoryBlockRegistry`) garantizando cero fuga al sistema operativo real.
* **Simulación**: Ejecutada por el motor en `simulation/engine.py`. El tráfico de red del motor de simulación interno se envía únicamente contra sockets del mismo proceso para escenarios internos (`inprocess`), o explícitamente se confina a la resolución local y rechaza destinos externos con la guardia `assert_loopback`.

## Modelo de Datos y Almacenamiento

El almacenamiento usa `SQLite` (configurable vía URL). El motor persiste metadatos analíticos y de seguridad:
* **Tabla `security_events`**: Alamacena eventos puros del sistema, con atributos de fuente, tipo y severidad (`LOW`, `HIGH`).
* **Tabla `incidents`**: Documenta instancias de brechas registradas, su estado, tiempo de vida y metadatos relevantes.
* **Tabla `incident_actions`**: Una bitácora inmutable de transiciones de estado para incidentes (quién, qué cambió, detalles).

Los bloqueos de clientes (contención) son de **memoria de proceso** (`InMemoryBlockRegistry`). No se persisten al disco para prevenir que el laboratorio quede inoperable tras reinicios.

**Sustitución de SQLite**: 
El almacenamiento está acoplado de forma débil implementando protocolos estándar. Para sustituir `SQLite` por un entorno volátil, el laboratorio implementa `MemoryEventRepository` y `MemoryIncidentRepository` respetando las firmas definidas en `storage/base.py` sin necesidad de tocar rutas de alto nivel.

## Estados de un Incidente

Un incidente pasa por un ciclo de vida unilateral gestionado por la API para fines de investigación:
```text
          +-------------+
          |  DETECTED   |
          +------+------+
                 | (Acknowledge)
          +------v------+
          |INVESTIGATING|
          +------+------+
                 | (Contain)
          +------v------+
          |  CONTAINED  |
          +------+------+
                 | (Resolve)
          +------v------+
          | RECOVERING  |
          +------+------+
                 | (Pase de Health Gate)
          +------v------+
          |  RESOLVED   |
          +-------------+
```
*(Si `RECOVERING` falla los tests de salud locales, el incidente es devuelto para corrección sin poder avanzar).*

## Eventos Sintéticos y Simulación

El sistema provee endpoints y un motor de **eventos sintéticos**. Estos son tráficos y métricas que emulan actividad de anomalías (tales como presión de conexiones o ráfagas UDP) para la ejecución de escenarios sin que el atacante o el origen existan de forma remota. Estos eventos están marcados estructuralmente con un flag inmutable `simulation: true` para diferenciarse de los eventos del entorno del usuario que está corriendo el laboratorio, y ser fácilmente descartables.
