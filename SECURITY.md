# Política de Seguridad

Este repositorio aloja **Wardline**, un laboratorio puramente **educativo** diseñado para ser desplegado de forma estricta y exclusiva en un entorno local (`127.0.0.1`).

## Advertencias de Despliegue

* **Entorno Restringido**: Wardline no ha sido diseñado ni auditado para ser expuesto en una red no confiable, en producción, o en Internet pública.
* **Mecanismos Lógicos**: Muchos controles (bloqueos, rate limiting) funcionan únicamente a nivel de memoria de proceso de la aplicación, sin escalar a firewalls del sistema operativo.
* **Secretos de Desarrollo**: Las claves de configuración y usuarios por defecto que figuran en la documentación o código (como las ficticias `dev-viewer-key`, `dev-operator-key`, `dev-admin-key`) son deliberadamente estáticas para el contexto formativo.

## Reporte de Vulnerabilidades

Si has encontrado un defecto o una vulnerabilidad real que contravenga las restricciones del propio entorno del laboratorio (por ejemplo, una forma de obligar al simulador a realizar peticiones fuera de localhost, o una fuga de configuraciones), te rogamos **abrir un informe de problema (Issue) en el repositorio** o contactar directamente con los mantenedores de manera privada si se trata de un escape del entorno sandbox local de extrema gravedad.
