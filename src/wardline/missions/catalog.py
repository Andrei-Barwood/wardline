"""Catalog of educational missions for Wardline."""

from wardline.missions.models import Mission

MISSIONS: tuple[Mission, ...] = (
    Mission(
        id="m01",
        chapter=1,
        title="Mantén el servicio en pie",
        objective=(
            "Verificar la disponibilidad local de los servicios y la emisión de registros "
            "estructurados."
        ),
        context=(
            "La infraestructura de la ciudad de Halcyon se encuentra bajo presión "
            "constante en este primer capítulo. Como operador defensivo, debes asegurar "
            "que los componentes esenciales del laboratorio respondan localmente y "
            "registren su actividad sin interrupciones. La resiliencia inicial depende "
            "de una línea base operativa sólida y observable."
        ),
        concept="disponibilidad",
        required_action=(
            "Iniciar los servicios locales y comprobar que responden a comprobaciones "
            "de salud y emiten registros."
        ),
        expected_result=(
            "Todos los componentes en estado saludable y al menos una línea registrada "
            "en el registro de aplicación."
        ),
        explanation=(
            "En un entorno hostil como la ciudad de Halcyon, la disponibilidad es la "
            "primera línea defensiva. Un servicio debe responder de manera predecible a "
            "través de sus canales HTTP, TCP y UDP mientras mantiene trazabilidad "
            "mediante registros estructurados en formato JSON. Si un componente crítico cae "
            "o deja de emitir eventos en el registro local, el sistema pierde visibilidad "
            "operativa y capacidad de respuesta. Mantener todos los componentes en estado "
            "saludable garantiza la continuidad del servicio defensivo ante la presión "
            "operativa constante."
        ),
    ),
    Mission(
        id="m02",
        chapter=2,
        title="Quién eres",
        objective=(
            "Comprobar los límites de autenticación y la jerarquía de autorización en las "
            "operaciones críticas."
        ),
        context=(
            "En el segundo capítulo de Halcyon, el control de acceso determina la "
            "integridad de las defensas. Las peticiones anónimas deben rechazarse de "
            "inmediato en los recursos protegidos para evitar accesos no autorizados. "
            "Además, las acciones de contención quedan restringidas a roles operativos "
            "superiores para impedir manipulaciones accidentales o indebidas."
        ),
        concept="identidad",
        required_action=(
            "Verificar que una petición sin credenciales devuelva 401 y que un usuario con "
            "rol de observador no pueda contener incidentes recibiendo 403."
        ),
        expected_result=(
            "Rechazo con código 401 ante accesos anónimos y código 403 ante permisos "
            "insuficientes para la contención."
        ),
        explanation=(
            "El principio de privilegio mínimo y la verificación estricta de identidad "
            "protegen los recursos administrativos del laboratorio. En Halcyon, cualquier "
            "intento de acceso anónimo a rutas sensibles debe ser rechazado inmediatamente "
            "con código 401, mientras que las operaciones críticas como la contención de "
            "incidentes quedan reservadas exclusivamente a operadores y administradores, "
            "impidiendo que usuarios de solo lectura modifiquen el estado defensivo. La "
            "frontera de autorización firme evita escaladas no autorizadas y garantiza que "
            "cada acción quede atribuida correctamente."
        ),
    ),
    Mission(
        id="m03",
        chapter=3,
        title="Baja el ritmo",
        objective=(
            "Ejercer el mecanismo de limitación de tasa mediante cubos de fichas y verificar "
            "el registro de eventos."
        ),
        context=(
            "Durante el tercer capítulo, los sistemas de Halcyon reciben oleadas súbitas "
            "de peticiones repetitivas. Para salvaguardar la estabilidad, el laboratorio "
            "implementa limitadores de tasa basados en cubos de fichas. Este control "
            "defensivo absorbe fluctuaciones normales pero restringe cualquier exceso que "
            "amenace con saturar los recursos."
        ),
        concept="límite de ritmo",
        required_action=(
            "Ejecutar una simulación de ráfaga y verificar el comportamiento de denegación "
            "del limitador ante peticiones concurrentes."
        ),
        expected_result=(
            "Detección de evento sintético de exceso de tasa y bloqueo de peticiones "
            "adicionales tras agotar las fichas disponibles."
        ),
        explanation=(
            "El control de ritmo mediante cubos de fichas previene la saturación y la "
            "degradación del servicio ante ráfagas desmedidas de tráfico en Halcyon. Cuando "
            "un cliente excede su cuota asignada, el sistema deniega peticiones adicionales "
            "y registra un evento sintético de abuso de tasa sin comprometer la estabilidad "
            "global del laboratorio. Este mecanismo defensivo permite absorber picos "
            "legítimos mientras aísla comportamientos anómalos de manera proporcional y "
            "automática."
        ),
    ),
    Mission(
        id="m04",
        chapter=4,
        title="Observa el tráfico",
        objective=(
            "Identificar patrones de presión en conexiones mediante la recolección "
            "append-only de eventos defensivos."
        ),
        context=(
            "En el cuarto capítulo, la visibilidad del tráfico se vuelve vital para la "
            "supervivencia de Halcyon. Los defensores monitorean métricas y eventos "
            "acumulados en repositorios locales seguros. Correlacionar secuencias de eventos "
            "permite anticipar anomalías y actuar antes de que afecten la operación general."
        ),
        concept="observabilidad",
        required_action=(
            "Simular presión de conexiones y comprobar la persistencia de eventos "
            "sintéticos y el conteo en el resumen de seguridad."
        ),
        expected_result=(
            "Presencia de eventos sintéticos de presión de conexiones y registro de al "
            "menos un evento en el resumen."
        ),
        explanation=(
            "La observabilidad continua es indispensable para detectar anomalías antes de "
            "que provoquen interrupciones severas en los servicios de Halcyon. Mediante la "
            "recolección append-only de eventos de seguridad y el cálculo de resúmenes "
            "operativos, los defensores identifican patrones de presión inusual en las "
            "conexiones locales. El registro estructurado proporciona el contexto temporal "
            "y de severidad necesario para correlacionar anomalías y activar alertas "
            "defensivas oportunas."
        ),
    ),
    Mission(
        id="m05",
        chapter=5,
        title="Restablece el sistema",
        objective=(
            "Ejecutar el ciclo completo de respuesta ante incidentes: reconocimiento, contención, "
            "validación de salud y resolución."
        ),
        context=(
            "El quinto capítulo presenta el desafío definitivo para la estabilidad de "
            "Halcyon: responder a un incidente y restaurar el servicio. El equipo "
            "defensivo contiene la anomalía aplicando bloqueos selectivos al cliente "
            "infractor. Finalmente, una vez verificada la salud de toda la infraestructura, "
            "el incidente se resuelve de forma segura."
        ),
        concept="recuperación",
        required_action=(
            "Crear un incidente sintético, avanzar por contención y resolverlo verificando "
            "el estado saludable de los servicios."
        ),
        expected_result=(
            "Incidente en estado final resuelto con desbloqueo selectivo tras confirmar "
            "salud completa del sistema."
        ),
        explanation=(
            "La resiliencia operativa culmina en un ciclo cerrado de contención y "
            "recuperación coordinada. Cuando un cliente genera una anomalía en Halcyon, "
            "el sistema transiciona el incidente a contención y aplica un bloqueo lógico "
            "temporal. Tras investigar y corregir la causa, el proceso de resolución "
            "verifica rigurosamente la salud de todos los componentes locales antes de "
            "restablecer el servicio y levantar selectivamente los bloqueos vigentes, "
            "asegurando un retorno seguro al estado operativo normal."
        ),
    ),
)

_MISSIONS_BY_ID: dict[str, Mission] = {m.id: m for m in MISSIONS}


def get_mission(mission_id: str) -> Mission | None:
    """Retrieve a mission by its unique identifier."""
    return _MISSIONS_BY_ID.get(mission_id)
