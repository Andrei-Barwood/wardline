<div align="center">
  <h1>🛡️ Wardline</h1>
  <p><strong>Laboratorio Defensivo Local e Interactivo para el Entrenamiento en Seguridad Aplicada</strong></p>
  <p>
    <a href="docs/architecture.md">Arquitectura</a> •
    <a href="docs/threat-model.md">Modelo de Amenazas</a> •
    <a href="docs/deployment.md">Despliegue</a> •
    <a href="docs/missions.md">Misiones</a>
  </p>
</div>

---

**Wardline** es un entorno educativo rigurosamente diseñado para enseñar los fundamentos de la defensa en capa de red y aplicación. Operando bajo estrictas reglas de "fallo cerrado" y aislamiento, el sistema solo escucha en interfaces de bucle local (`127.0.0.1`), proveyendo un espacio *sandbox* seguro para aprender sobre rate limits, circuit breakers, respuesta a incidentes y análisis de anomalías HTTP, TCP y UDP.

> [!WARNING]
> Este proyecto tiene fines **exclusivamente formativos**. Todo el tráfico, mitigación y simulación está confinado lógicamente en la memoria del proceso local. Consulta nuestro [Modelo de Amenazas](docs/threat-model.md) y nuestra [Política de Seguridad](SECURITY.md) antes de empezar.

---

## 🎯 12 Tutoriales Rápidos de Aprendizaje

Explora la funcionalidad completa del laboratorio ejecutando los siguientes escenarios desde tu terminal.

### Tutorial 1: Arranque Seguro del Laboratorio
Inicia la infraestructura de Wardline. Por diseño, los servidores bloquean intentos de escucha pública y se levantan silenciosamente en `loopback`.
```bash
./scripts/run.sh
```
*Si prefieres Docker:* `docker compose up --build` (garantizado también sin privilegios y hacia `127.0.0.1`).

### Tutorial 2: Chequeo de Salud Transparente
Una vez activo, comprueba la superficie pública. Wardline expone solo `/health` y `/version` de forma pública. Note que `/health` oculta detalles y contraseñas.
```bash
curl -sS http://127.0.0.1:8080/health | jq
```

### Tutorial 3: Identidad y el Rol "Viewer"
La autenticación es jerárquica. Prueba acceder al resumen de seguridad anónimamente (recibirás un HTTP 401) y luego asume el rol de observador usando una llave ficticia preconfigurada en desarrollo.
```bash
# Fallo:
curl -I http://127.0.0.1:8080/security/summary
# Éxito:
curl -sS -H "Authorization: Bearer dev-viewer-key" http://127.0.0.1:8080/security/summary | jq
```

### Tutorial 4: Generación de Presión Simulada Local
Wardline integra un simulador `inprocess`. Puedes generar una tormenta asíncrona de eventos UDP sin siquiera abrir un puerto real hacia tu sistema operativo.
```bash
python -m wardline.simulation --scenario udp_burst --mode inprocess
```

### Tutorial 5: Simulador Controlado por la API (Operator)
Alternativamente, un operador con los permisos adecuados puede detonar escenarios de "abuso de conexiones" desde la API REST.
```bash
curl -sS -X POST http://127.0.0.1:8080/simulation/run \
  -H "Authorization: Bearer dev-operator-key" \
  -H "Content-Type: application/json" \
  -d '{"scenario":"connection_pressure", "mode":"inprocess"}'
```

### Tutorial 6: Detección Continua (Eventos y Anomalías)
La presión inyectada en los pasos anteriores dispara métricas e infiere anomalías de forma pasiva. Audita la base de datos de eventos para observar cómo Wardline cataloga la ráfaga.
```bash
curl -sS "http://127.0.0.1:8080/events?simulation=true" \
  -H "Authorization: Bearer dev-viewer-key" | jq '.events[] | .event_type'
```

### Tutorial 7: Listado de Incidentes Activos
Cuando una anomalía cruza el umbral defensivo, se cataloga automáticamente un `Incidente`. Visualiza el estatus del incidente que la simulación originó:
```bash
curl -sS http://127.0.0.1:8080/incidents \
  -H "Authorization: Bearer dev-viewer-key" | jq
```

### Tutorial 8: Reconocimiento Operativo (Acknowledge)
El ciclo de vida de incidentes de Wardline exige reconocimiento humano. Toma el ID del incidente del tutorial anterior y transicionalo al estado `INVESTIGATING`. *(El rol Viewer recibirá un 403; debes ser al menos Operator).*
```bash
INCIDENT_ID="<tu_incident_id>"
curl -sS -X POST "http://127.0.0.1:8080/incidents/${INCIDENT_ID}/acknowledge" \
  -H "Authorization: Bearer dev-operator-key"
```

### Tutorial 9: Contención de Amenazas
Para cortar una amenaza sin tocar Firewalls locales (que no están permitidos), aplicamos una contención lógica en la memoria de la aplicación.
```bash
curl -sS -X POST "http://127.0.0.1:8080/incidents/${INCIDENT_ID}/contain" \
  -H "Authorization: Bearer dev-operator-key"
```

### Tutorial 10: Circuitos y Límites en Acción (Rate Limiting)
Experimenta en vivo el rechazo. Dispara ráfagas a un endpoint validado y mira cómo el _Token Bucket Limiter_ se agota, retornando un `HTTP 429 Too Many Requests`.
```bash
for i in {1..30}; do
  curl -o /dev/null -s -w "%{http_code}\n" \
  -H "Authorization: Bearer dev-viewer-key" \
  http://127.0.0.1:8080/metrics
done
```

### Tutorial 11: Misiones del Operador (Checks)
Wardline provee un motor de "misiones" interactivas (m01 a m05) para comprobar que los controles actúan correctamente. Comprueba que el control limitador (m03) haya atrapado efectivamente el abuso de ráfagas.
```bash
curl -sS -X POST http://127.0.0.1:8080/missions/m03/check \
  -H "Authorization: Bearer dev-operator-key" | jq
```

### Tutorial 12: Recuperación Administrativa (Rollback)
Finalmente, los Administradores tienen la llave maestra de la API. Pueden ejecutar un _rollback_ de configuraciones o relajar reglas para restablecer el servicio, sin arriesgar el host del estudiante.
```bash
curl -sS -X POST http://127.0.0.1:8080/admin/recovery/rollback \
  -H "Authorization: Bearer dev-admin-key" | jq
```

---

## 🏗️ Requisitos y Setup

Wardline está desarrollado en **Python 3.12+**. 

```bash
# 1. Instalar el entorno
./scripts/setup.sh

# 2. Correr la batería técnica de tests y comprobaciones SAST
./scripts/test.sh

# 3. Iniciar el laboratorio de forma segura
./scripts/run.sh
```

Para más detalles acerca de las decisiones de diseño, consulta [docs/architecture.md](docs/architecture.md). Para lineamientos de contribución técnica, visita [CONTRIBUTING.md](CONTRIBUTING.md).
