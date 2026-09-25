# Hardening de Wardline

**Fecha**: 2026-09-23

Este documento registra las validaciones técnicas y decisiones de endurecimiento realizadas sobre el laboratorio Wardline para asegurar su contención y minimizar su superficie de ataque, cumpliendo su propósito como un entorno de entrenamiento puramente local.

## Comprobaciones Automatizadas y Resultados

Todos estos controles están verificados por la suite de regresión (`tests/security/test_hardening_regression.py`) y garantizan el estado cerrado del laboratorio por diseño:

1. **Restricción de Interfaces de Red**: `validate_settings` rechaza configuraciones de host hacia `0.0.0.0` o IPs públicas en `http_host` y `tcp_host`. Solo se aceptan `127.0.0.1`, `localhost` y `::1`. (El centinela `container` está soportado explícitamente solo mediante su flag). **[Corregido / Pasa]**
2. **Desactivación de Documentación Automática Pública**: La función `create_app` inicializa FastAPI con `docs_url=None`, `redoc_url=None` y `openapi_url=None`. **[Corregido / Pasa]**
3. **Superficie Pública Estricta**: Las únicas rutas accesibles sin un token de autenticación configurado (`Authorization: Bearer <key>`) son `/health` y `/version`. **[Corregido / Pasa]**
4. **Acotamiento del Simulador**: El controlador HTTP de simulación (`SimulationRunRequest`) no permite especificar el `host` de destino. **[Corregido / Pasa]**
5. **Simulador inprocess**: El simulador por defecto genera y consume el tráfico internamente interactuando con los servidores sin utilizar descriptores de red ni abrir sockets (`socket.create_connection` no se invoca en inprocess). **[Corregido / Pasa]**
6. **Contención del Proceso y Dependencias Ofensivas**: El árbol de código fuente `src/` no contiene módulos riesgosos ni dependencias de ataque (ausencia de `subprocess.`, `eval(`, `exec(`, `os.system`, `pickle.loads`, `verify=False`, `iptables`, `pfctl`, `scapy`, `nmap`). **[Corregido / Pasa]**
7. **Filtrado de Secretos**: Los secretos predeterminados (`dev-viewer-key`, `dev-operator-key`, `dev-admin-key`) no se incluyen en el código de producción. Además, `/health` no los expone. **[Corregido / Pasa]**
8. **Fallos Cerrados (Fail Safely)**: Los errores de servidor 500 están centralizados, devolviendo un cuerpo de respuesta `internal error` sin fugas de `Traceback` o trazas de memoria. **[Corregido / Pasa]**
9. **Despliegue de Docker Restringido**: El archivo `docker-compose.yml` mapea exclusivamente la interfaz loopback (`127.0.0.1:8080:8080`) y revoca todos los privilegios (`cap_drop: ALL`). **[Corregido / Pasa]**
10. **Seguridad en CI/CD**: El flujo de GitHub Actions no utiliza directivas de escalamiento o inyección (como `pull_request_target`). **[Corregido / Pasa]**
11. **Bloqueo Restringido a Lógica y Memoria**: El gestor de denegación (`BlockRegistry`) actúa por identidad cliente y no por estado de red (carece del método `block_ip`), garantizando que la IP loopback compartida no pueda ser auto-denegada accidentalmente por el administrador de red. **[Corregido / Pasa]**
12. **Ausencia de Rutas Críticas No Solicitadas**: Rutas como `/debug`, `/shutdown`, y `/eval` no existen. **[Corregido / Pasa]**
13. **Ausencia de Inseguridades Web (CORS/Static)**: No se publican directivas amplias como `allow_origins "*"` ni se exponen montajes estáticos. **[Corregido / Pasa]**

*(Nota: Las versiones de los paquetes del entorno se mantienen fijadas a través del entorno virtual original generado por `pyproject.toml`, por lo que las dependencias transitivas no introducen librerías de red externas)*.
