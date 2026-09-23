from unittest.mock import Mock

from wardline.contracts import ServiceName
from wardline.security.circuit_breaker import CircuitBreaker, CircuitBreakerRegistry


def test_circuit_opens_after_threshold() -> None:
    time_mock = Mock(return_value=100.0)
    breaker = CircuitBreaker(threshold=3, window_seconds=10.0, open_seconds=5.0, time_fn=time_mock)

    assert breaker.allow() is True
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == "closed"
    assert breaker.allow() is True

    breaker.record_failure()
    assert breaker.state == "open"
    assert breaker.allow() is False


def test_circuit_half_open_allows_one_probe() -> None:
    time_mock = Mock(return_value=100.0)
    breaker = CircuitBreaker(threshold=1, window_seconds=10.0, open_seconds=5.0, time_fn=time_mock)
    breaker.record_failure()
    assert breaker.state == "open"
    assert breaker.allow() is False

    time_mock.return_value = 106.0
    assert breaker.state == "half_open"
    assert breaker.allow() is True
    assert breaker.allow() is False  # Only one probe allowed


def test_circuit_failure_on_probe_reopens() -> None:
    time_mock = Mock(return_value=100.0)
    breaker = CircuitBreaker(threshold=1, window_seconds=10.0, open_seconds=5.0, time_fn=time_mock)
    breaker.record_failure()

    time_mock.return_value = 106.0
    assert breaker.allow() is True
    breaker.record_failure()

    assert breaker.state == "open"
    assert breaker.allow() is False


def test_circuit_success_on_probe_closes() -> None:
    time_mock = Mock(return_value=100.0)
    breaker = CircuitBreaker(threshold=1, window_seconds=10.0, open_seconds=5.0, time_fn=time_mock)
    breaker.record_failure()

    time_mock.return_value = 106.0
    assert breaker.allow() is True
    breaker.record_success()

    assert breaker.state == "closed"
    assert breaker.allow() is True


def test_breaker_callback_exception_does_not_break_transition() -> None:
    time_mock = Mock(return_value=100.0)

    def failing_callback(state: str) -> None:
        raise ValueError("Boom")

    breaker = CircuitBreaker(
        threshold=1,
        window_seconds=10.0,
        open_seconds=5.0,
        time_fn=time_mock,
        on_change=failing_callback,
    )

    breaker.record_failure()
    assert breaker.state == "open"  # Transition succeeded despite callback error


def test_registry_records_failures() -> None:
    registry = CircuitBreakerRegistry(threshold=1, window_seconds=10.0, open_seconds=5.0)
    assert registry.allow(ServiceName.HTTP) is True
    registry.record_failure(ServiceName.HTTP)
    assert registry.allow(ServiceName.HTTP) is False
    assert registry.allow(ServiceName.TCP) is True  # Only HTTP breaker is open
