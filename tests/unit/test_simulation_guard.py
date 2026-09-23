import pytest

from wardline.simulation.guard import assert_loopback
from wardline.simulation.scenarios import SimulationRefused


def test_assert_loopback_accepts_localhost():
    assert_loopback("127.0.0.1")
    assert_loopback("localhost")
    assert_loopback("::1")


def test_assert_loopback_rejects_external():
    with pytest.raises(SimulationRefused):
        assert_loopback("8.8.8.8")

    with pytest.raises(SimulationRefused):
        assert_loopback("203.0.113.10")

    with pytest.raises(SimulationRefused):
        assert_loopback("10.0.0.1")

    with pytest.raises(SimulationRefused):
        assert_loopback("0.0.0.0")

    with pytest.raises(SimulationRefused):
        assert_loopback("example.com")

    with pytest.raises(SimulationRefused):
        assert_loopback("")
