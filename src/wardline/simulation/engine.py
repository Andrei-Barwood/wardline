import asyncio
import socket
import uuid

import httpx

from wardline.contracts import SecurityEvent, ServiceName, Severity
from wardline.runtime import AppState
from wardline.security.events import record_event
from wardline.simulation.guard import (
    SIMULATION_MAX_CONNECTIONS,
    SIMULATION_MAX_DATAGRAMS,
    SIMULATION_MAX_HEALTH_REQUESTS,
    SIMULATION_MAX_INVALID_LINES,
    assert_loopback,
)
from wardline.simulation.scenarios import (
    SimulationMode,
    SimulationRefused,
    SimulationResult,
    SimulationScenario,
)


def _get_viewer_key(state: AppState) -> str | None:
    from wardline.auth.api_keys import parse_dev_api_keys
    from wardline.contracts import Role

    try:
        parsed = parse_dev_api_keys(state.settings.dev_api_keys)
        return parsed.get(Role.VIEWER)
    except Exception:
        return None


def _record_synthetic_event(
    state: AppState,
    event_type: str,
    service: ServiceName,
    severity: Severity,
    sequence: int,
    correlation_id: str,
) -> None:
    event = SecurityEvent(
        timestamp=state.clock.now(),
        source="training-client",
        service=service,
        event_type=event_type,
        severity=severity,
        simulation=True,
        action="recorded",
        correlation_id=correlation_id,
        details={"synthetic": True, "sequence": sequence},
    )
    record_event(state, event)


def _handle_refusal(state: AppState, reason: str, correlation_id: str) -> None:
    event = SecurityEvent(
        timestamp=state.clock.now(),
        source="training-client",
        service=ServiceName.MONITORING,
        event_type="security_simulation_refused",
        severity=Severity.LOW,
        simulation=True,
        action="recorded",
        correlation_id=correlation_id,
        details={"synthetic": True, "reason": reason},
    )
    record_event(state, event)


async def simulate_burst(state: AppState, *, mode: SimulationMode) -> SimulationResult:
    correlation_id = str(uuid.uuid4())
    scenario = SimulationScenario.burst
    try:
        if mode == SimulationMode.loopback:
            assert_loopback(state.settings.http_host)
            key = _get_viewer_key(state)
            if not key:
                raise SimulationRefused(True, "viewer_key_not_configured", correlation_id)

            port = state.settings.http_port
            if port == 0:
                raise SimulationRefused(True, "service_not_running", correlation_id)

            try:
                async with httpx.AsyncClient(
                    base_url=f"http://{state.settings.http_host}:{port}"
                ) as client:
                    for _ in range(SIMULATION_MAX_HEALTH_REQUESTS):
                        await client.get("/health", headers={"Authorization": f"Bearer {key}"})
            except Exception:
                pass

        for i in range(1, 6):
            _record_synthetic_event(
                state, "simulated_rate_abuse", ServiceName.HTTP, Severity.MEDIUM, i, correlation_id
            )
        return SimulationResult(scenario, mode, 5, False, None, correlation_id)

    except SimulationRefused as e:
        _handle_refusal(state, e.reason, correlation_id)
        return SimulationResult(scenario, mode, 0, True, e.reason, correlation_id)


async def simulate_invalid_messages(state: AppState, *, mode: SimulationMode) -> SimulationResult:
    correlation_id = str(uuid.uuid4())
    scenario = SimulationScenario.invalid_messages
    try:
        if mode == SimulationMode.loopback:
            assert_loopback(state.settings.tcp_host)
            key = _get_viewer_key(state)
            if not key:
                raise SimulationRefused(True, "viewer_key_not_configured", correlation_id)

            port = state.settings.tcp_port
            if port == 0:
                raise SimulationRefused(True, "service_not_running", correlation_id)

            try:
                reader, writer = await asyncio.open_connection(state.settings.tcp_host, port)
                writer.write(
                    (
                        f'{{"type": "hello", "client_id": "training-client", "token": "{key}"}}\n'
                    ).encode()
                )
                await writer.drain()
                await reader.readline()

                for _ in range(SIMULATION_MAX_INVALID_LINES):
                    writer.write(b"this is not json\n")
                    await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        for i in range(1, 4):
            _record_synthetic_event(
                state, "simulated_invalid_input", ServiceName.TCP, Severity.LOW, i, correlation_id
            )
        return SimulationResult(scenario, mode, 3, False, None, correlation_id)

    except SimulationRefused as e:
        _handle_refusal(state, e.reason, correlation_id)
        return SimulationResult(scenario, mode, 0, True, e.reason, correlation_id)


async def simulate_connection_pressure(
    state: AppState, *, mode: SimulationMode
) -> SimulationResult:
    correlation_id = str(uuid.uuid4())
    scenario = SimulationScenario.connection_pressure
    try:
        if mode == SimulationMode.loopback:
            assert_loopback(state.settings.tcp_host)
            key = _get_viewer_key(state)
            if not key:
                raise SimulationRefused(True, "viewer_key_not_configured", correlation_id)

            port = state.settings.tcp_port
            if port == 0:
                raise SimulationRefused(True, "service_not_running", correlation_id)

            writers = []
            try:
                for _ in range(SIMULATION_MAX_CONNECTIONS):
                    _, writer = await asyncio.open_connection(state.settings.tcp_host, port)
                    writers.append(writer)
            except Exception:
                pass
            finally:
                for w in writers:
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception:
                        pass

        for i in range(1, 6):
            _record_synthetic_event(
                state,
                "simulated_connection_pressure",
                ServiceName.TCP,
                Severity.HIGH,
                i,
                correlation_id,
            )
        return SimulationResult(scenario, mode, 5, False, None, correlation_id)

    except SimulationRefused as e:
        _handle_refusal(state, e.reason, correlation_id)
        return SimulationResult(scenario, mode, 0, True, e.reason, correlation_id)


async def simulate_udp_burst(state: AppState, *, mode: SimulationMode) -> SimulationResult:
    correlation_id = str(uuid.uuid4())
    scenario = SimulationScenario.udp_burst
    try:
        if mode == SimulationMode.loopback:
            assert_loopback(state.settings.udp_host)
            key = _get_viewer_key(state)
            if not key:
                raise SimulationRefused(True, "viewer_key_not_configured", correlation_id)

            port = state.settings.udp_port
            if port == 0:
                raise SimulationRefused(True, "service_not_running", correlation_id)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = (
                    f'{{"client_id": "training-client", "token": "{key}", "seq": 1, "data": "A"}}'
                ).encode()
                for _ in range(SIMULATION_MAX_DATAGRAMS):
                    sock.sendto(payload, (state.settings.udp_host, port))
                sock.close()
            except Exception:
                pass

        for i in range(1, 4):
            _record_synthetic_event(
                state, "simulated_udp_burst", ServiceName.UDP, Severity.MEDIUM, i, correlation_id
            )
        return SimulationResult(scenario, mode, 3, False, None, correlation_id)

    except SimulationRefused as e:
        _handle_refusal(state, e.reason, correlation_id)
        return SimulationResult(scenario, mode, 0, True, e.reason, correlation_id)


async def simulate_all(state: AppState, *, mode: SimulationMode) -> SimulationResult:
    correlation_id = str(uuid.uuid4())
    scenario = SimulationScenario.all

    if mode == SimulationMode.loopback:
        try:
            # We can just verify pre-conditions first
            assert_loopback(state.settings.http_host)
            key = _get_viewer_key(state)
            if not key:
                raise SimulationRefused(True, "viewer_key_not_configured", correlation_id)
            if state.settings.http_port == 0:
                raise SimulationRefused(True, "service_not_running", correlation_id)
        except SimulationRefused as e:
            _handle_refusal(state, e.reason, correlation_id)
            return SimulationResult(scenario, mode, 0, True, e.reason, correlation_id)

    events = 0
    res1 = await simulate_burst(state, mode=mode)
    res2 = await simulate_invalid_messages(state, mode=mode)
    res3 = await simulate_connection_pressure(state, mode=mode)
    res4 = await simulate_udp_burst(state, mode=mode)

    events = (
        res1.events_recorded + res2.events_recorded + res3.events_recorded + res4.events_recorded
    )

    return SimulationResult(scenario, mode, events, False, None, correlation_id)
