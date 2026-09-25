# Guía de Contribución

Gracias por tu interés en contribuir a Wardline. Este laboratorio defensivo tiene fines estrictamente educativos y locales.

## Preparación del Entorno

Para preparar tu entorno de desarrollo, utiliza el script proporcionado:
```bash
./scripts/setup.sh
```
Este script instalará las dependencias necesarias en un entorno virtual y configurará los hooks pre-commit (si los hubiera).

## Ejecución de Pruebas

Para asegurar la calidad del código, ejecuta la suite de pruebas localmente mediante:
```bash
./scripts/test.sh
```
Nuestra integración continua requiere que las pruebas aprueben con una cobertura mínima del 70%.

## Convenciones de Código

* **Tipado Estático**: Utilizamos anotaciones de tipo estrictas. Ejecuta `mypy src` para verificar.
* **Formato y Linting**: Usamos `ruff`. Ejecuta `ruff check src tests` antes de enviar cambios.

## Reglas Estrictas de Seguridad

No se aceptarán Pull Requests que violen las siguientes premisas:
1. **Red Fuera de Loopback**: Cualquier cambio que exponga la aplicación a escuchar en `0.0.0.0` o fuera de las interfaces `127.0.0.1`, `localhost` o `::1` será rechazado (exceptuando el flujo de Docker explícitamente contenido).
2. **Dependencias Ofensivas**: No se admitirán herramientas ofensivas o de ataque (p.ej. nmap, scapy de forma ofensiva).
3. **Simulador Abierto**: No se aceptarán parches que conviertan el simulador interno en un generador de tráfico configurable para destinos externos.
4. **Credenciales**: No deben incluirse claves, tokens, ni credenciales reales en el árbol de código en ningún momento. Solo se admiten valores ficticios provistos en `.env.example`.

*(Nota: El archivo README.md será completado al finalizar la campaña del proyecto).*
