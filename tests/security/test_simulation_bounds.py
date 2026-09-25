
import pytest
from httpx import AsyncClient

from wardline.simulation.engine import assert_loopback
from wardline.simulation.scenarios import SimulationRefused


@pytest.mark.asyncio
async def test_simulation_extra_host(stack):
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.post("/simulation/run", headers={"Authorization": "Bearer dev-admin-key"}, json={"scenario": "burst", "host": "10.0.0.1"}) # noqa: E501
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "validation_error"

def test_assert_loopback():
    with pytest.raises(SimulationRefused):
        assert_loopback("example.com")
