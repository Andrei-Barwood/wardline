# Despliegue de Wardline

Wardline está diseñado para ejecutarse localmente de forma segura. Por defecto, solo escucha en las interfaces loopback (`127.0.0.1`, `localhost`, `::1`) para evitar la exposición accidental de la red.

## Arranque sin Docker (Por defecto)

Para desplegar Wardline directamente en tu sistema:
1. Crea un entorno virtual y actívalo: `python3 -m venv .venv && source .venv/bin/activate`
2. Instala la aplicación: `pip install .`
3. Ejecuta la aplicación: `python -m wardline`

El proceso escuchará estrictamente en `127.0.0.1`.

## Arranque con Docker

Opcionalmente, puedes ejecutar Wardline utilizando Docker y Docker Compose para garantizar un entorno reproducible y aislado.

Para desplegar Wardline con Docker:
1. Asegúrate de tener Docker y Docker Compose instalados.
2. Ejecuta `docker-compose up --build` en el directorio raíz del proyecto.

### Seguridad y Tensión de Red en Docker

Cuando se ejecuta dentro de un contenedor Docker, escuchar únicamente en la interfaz loopback (`127.0.0.1`) del contenedor impide que Docker pueda enrutar el tráfico desde el anfitrión hacia el proceso (Docker reenvía los puertos a la interfaz `eth0` del contenedor, no a la interfaz local del contenedor).

Para resolver esta tensión de red sin abrir el laboratorio al anfitrión de forma accidental o usar la IP `0.0.0.0` abiertamente:
* Fuera de Docker, el valor por defecto sigue siendo estricto a `127.0.0.1`.
* Dentro de Docker, el archivo `docker-compose.yml` establece las variables `WARDLINE_HTTP_HOST`, `WARDLINE_TCP_HOST` y `WARDLINE_UDP_HOST` con el valor especial `"container"`, además de la bandera obligatoria `WARDLINE_CONTAINER=1`.
* Wardline solo aceptará el valor especial `"container"` si la variable `WARDLINE_CONTAINER=1` está presente. Internamente, en este caso particular, Wardline escuchará en todas las interfaces dentro del network namespace del contenedor para recibir el tráfico enrutado por Docker.
* **IMPORTANTE**: La publicación de puertos en el archivo `docker-compose.yml` (`127.0.0.1:8080:8080`) garantiza que Docker restrinja estrictamente el acceso a la interfaz local del **anfitrión**. No se acepta en ningún caso el uso literal de `0.0.0.0` como valor de host. Desde la red del anfitrión, solo se puede entrar a Wardline a través de loopback.

El contenedor se ejecuta sin privilegios de red o sistema (usuario `10001:10001`), con el sistema de archivos de solo lectura y los privilegios eliminados (`cap_drop: [ALL]`, `no-new-privileges:true`).
