# Catálogo de Misiones Educativas de Wardline

Este documento describe las cinco misiones educativas del laboratorio defensivo en la ciudad de Halcyon. Cada misión ejercita un concepto defensivo clave desarrollado a lo largo de los capítulos, permitiendo a los operadores verificar localmente el comportamiento de los controles.

---

## Misión m01 — Mantén el servicio en pie (Capítulo 1)

- **Identificador**: `m01`
- **Capítulo**: 1
- **Concepto defensivo**: Disponibilidad
- **Objetivo**: Verificar la disponibilidad local de los servicios y la emisión de registros estructurados.
- **Acción requerida**: Iniciar los servicios locales (HTTP, TCP, UDP) y confirmar que responden adecuadamente a las comprobaciones de salud y emiten líneas de registro JSON.
- **Resultado esperado**: Todos los componentes reportan estado saludable (`ok`) y se ha emitido al menos una línea en el registro de aplicación.
- **Cómo ejecutar el chequeo**:
  ```bash
  curl -X POST http://127.0.0.1:8080/missions/m01/check \
    -H "Authorization: Bearer <TOKEN_OPERATOR>"
  ```
- **Explicación**:
  En un entorno hostil como la ciudad de Halcyon, la disponibilidad es la primera línea defensiva. Un servicio debe responder de manera predecible a través de sus canales HTTP, TCP y UDP mientras mantiene trazabilidad mediante registros estructurados en formato JSON. Si un componente crítico cae o deja de emitir eventos en el registro local, el sistema pierde visibilidad operativa y capacidad de respuesta. Mantener todos los componentes en estado saludable garantiza la continuidad del servicio defensivo ante la presión operativa constante.

---

## Misión m02 — Quién eres (Capítulo 2)

- **Identificador**: `m02`
- **Capítulo**: 2
- **Concepto defensivo**: Identidad y autorización
- **Objetivo**: Comprobar los límites de autenticación y la jerarquía de autorización en las operaciones críticas.
- **Acción requerida**: Probar que las solicitudes anónimas a rutas protegidas se rechazan con código 401 y que un usuario con rol de observador no puede ejecutar acciones de contención, recibiendo código 403.
- **Resultado esperado**: Código 401 ante peticiones anónimas y 403 ante privilegios insuficientes.
- **Cómo ejecutar el chequeo**:
  ```bash
  curl -X POST http://127.0.0.1:8080/missions/m02/check \
    -H "Authorization: Bearer <TOKEN_OPERATOR>"
  ```
- **Explicación**:
  El principio de privilegio mínimo y la verificación estricta de identidad protegen los recursos administrativos del laboratorio. En Halcyon, cualquier intento de acceso anónimo a rutas sensibles debe ser rechazado inmediatamente con código 401, mientras que las operaciones críticas como la contención de incidentes quedan reservadas exclusivamente a operadores y administradores, impidiendo que usuarios de solo lectura modifiquen el estado defensivo. La frontera de autorización firme evita escaladas no autorizadas y garantiza que cada acción quede atribuida correctamente.

---

## Misión m03 — Baja el ritmo (Capítulo 3)

- **Identificador**: `m03`
- **Capítulo**: 3
- **Concepto defensivo**: Límite de ritmo (Rate Limiting)
- **Objetivo**: Ejercer el mecanismo de limitación de tasa mediante cubos de fichas y verificar el registro de eventos defensivos.
- **Acción requerida**: Ejecutar una simulación de ráfaga y comprobar que el limitador de fichas bloquea solicitudes que superan la capacidad asignada.
- **Resultado esperado**: Registro del evento sintético `simulated_rate_abuse` y denegación de solicitudes excesivas por el limitador.
- **Cómo ejecutar el chequeo**:
  ```bash
  curl -X POST http://127.0.0.1:8080/missions/m03/check \
    -H "Authorization: Bearer <TOKEN_OPERATOR>"
  ```
- **Explicación**:
  El control de ritmo mediante cubos de fichas previene la saturación y la degradación del servicio ante ráfagas desmedidas de tráfico en Halcyon. Cuando un cliente excede su cuota asignada, el sistema deniega peticiones adicionales y registra un evento sintético de abuso de tasa sin comprometer la estabilidad global del laboratorio. Este mecanismo defensivo permite absorber picos legítimos mientras aísla comportamientos anómalos de manera proporcional y automática.

---

## Misión m04 — Observa el tráfico (Capítulo 4)

- **Identificador**: `m04`
- **Capítulo**: 4
- **Concepto defensivo**: Observabilidad y métricas
- **Objetivo**: Identificar patrones de presión en conexiones mediante la recolección append-only de eventos defensivos.
- **Acción requerida**: Simular presión de conexiones simultáneas y verificar que los eventos sintéticos se reflejen en el repositorio y en el resumen de seguridad.
- **Resultado esperado**: Presencia de eventos `simulated_connection_pressure` y registro contable de simulaciones en el resumen defensivo.
- **Cómo ejecutar el chequeo**:
  ```bash
  curl -X POST http://127.0.0.1:8080/missions/m04/check \
    -H "Authorization: Bearer <TOKEN_OPERATOR>"
  ```
- **Explicación**:
  La observabilidad continua es indispensable para detectar anomalías antes de que provoquen interrupciones severas en los servicios de Halcyon. Mediante la recolección append-only de eventos de seguridad y el cálculo de resúmenes operativos, los defensores identifican patrones de presión inusual en las conexiones locales. El registro estructurado proporciona el contexto temporal y de severidad necesario para correlacionar anomalías y activar alertas defensivas oportunas.

---

## Misión m05 — Restablece el sistema (Capítulo 5)

- **Identificador**: `m05`
- **Capítulo**: 5
- **Concepto defensivo**: Recuperación y respuesta a incidentes
- **Objetivo**: Ejecutar el ciclo completo de respuesta ante incidentes: reconocimiento, contención, validación de salud y resolución.
- **Acción requerida**: Gestionar un incidente sintético a través de sus fases (`INVESTIGATING`, `CONTAINED`, `RECOVERING`, `RESOLVED`), asegurando la salud del sistema antes del levantamiento selectivo de bloqueos.
- **Resultado esperado**: Incidente en estado `RESOLVED` tras superar las comprobaciones de salud del gate local.
- **Cómo ejecutar el chequeo**:
  ```bash
  curl -X POST http://127.0.0.1:8080/missions/m05/check \
    -H "Authorization: Bearer <TOKEN_OPERATOR>"
  ```
- **Explicación**:
  La resiliencia operativa culmina en un ciclo cerrado de contención y recuperación coordinada. Cuando un cliente genera una anomalía en Halcyon, el sistema transiciona el incidente a contención y aplica un bloqueo lógico temporal. Tras investigar y corregir la causa, el proceso de resolución verifica rigurosamente la salud de todos los componentes locales antes de restablecer el servicio y levantar selectivamente los bloqueos vigentes, asegurando un retorno seguro al estado operativo normal.
