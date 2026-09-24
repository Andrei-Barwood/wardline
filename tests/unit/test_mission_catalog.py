from pathlib import Path

from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.auth.api_keys import parse_dev_api_keys
from wardline.contracts import Role
from wardline.missions.catalog import MISSIONS, get_mission
from wardline.runtime import build_state

_FORBIDDEN_TERMS = ("exploit", "payload", "shellcode", "nmap", "0day", "metasploit")


def test_catalog_has_five_stable_ids() -> None:
    assert len(MISSIONS) == 5
    expected_ids = ["m01", "m02", "m03", "m04", "m05"]
    assert [m.id for m in MISSIONS] == expected_ids
    assert [m.chapter for m in MISSIONS] == [1, 2, 3, 4, 5]


def test_titles_exact() -> None:
    expected_titles = {
        "m01": "Mantén el servicio en pie",
        "m02": "Quién eres",
        "m03": "Baja el ritmo",
        "m04": "Observa el tráfico",
        "m05": "Restablece el sistema",
    }
    for m in MISSIONS:
        assert m.title == expected_titles[m.id]


async def test_list_omits_explanation_detail_includes_it(settings_factory) -> None:
    state = build_state(settings_factory())
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    viewer_key = keys[Role.VIEWER]
    headers = {"Authorization": f"Bearer {viewer_key}"}

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # GET /missions list
        resp = await client.get("/missions", headers=headers)
        assert resp.status_code == 200
        data = resp.json()["missions"]
        assert len(data) == 5
        for item in data:
            assert "id" in item
            assert "chapter" in item
            assert "title" in item
            assert "objective" in item
            assert "explanation" not in item

        # GET /missions/{id} detail
        resp_detail = await client.get("/missions/m01", headers=headers)
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        assert detail["id"] == "m01"
        assert detail["title"] == "Mantén el servicio en pie"
        assert "explanation" in detail
        m01 = get_mission("m01")
        assert m01 is not None
        assert detail["explanation"] == m01.explanation


async def test_check_requires_operator(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    viewer_key = keys[Role.VIEWER]
    operator_key = keys[Role.OPERATOR]

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Viewer cannot check -> 403
        resp_v = await client.post(
            "/missions/m02/check",
            headers={"Authorization": f"Bearer {viewer_key}"},
        )
        assert resp_v.status_code == 403

        # Operator can check -> 200
        resp_op = await client.post(
            "/missions/m02/check",
            headers={"Authorization": f"Bearer {operator_key}"},
        )
        assert resp_op.status_code == 200
        assert resp_op.json()["mission_id"] == "m02"


async def test_unknown_mission_404(settings_factory) -> None:
    state = build_state(settings_factory())
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    operator_key = keys[Role.OPERATOR]
    headers = {"Authorization": f"Bearer {operator_key}"}

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Unknown mission detail -> 404
        resp_get = await client.get("/missions/m99", headers=headers)
        assert resp_get.status_code == 404
        assert resp_get.json()["error"]["code"] == "not_found"

        # Unknown mission check -> 404
        resp_post = await client.post("/missions/m99/check", headers=headers)
        assert resp_post.status_code == 404
        assert resp_post.json()["error"]["code"] == "not_found"


def test_mission_text_has_no_forbidden_terms() -> None:
    for mission in MISSIONS:
        for field in (
            mission.title,
            mission.objective,
            mission.context,
            mission.concept,
            mission.required_action,
            mission.expected_result,
            mission.explanation,
        ):
            lower = field.lower()
            for term in _FORBIDDEN_TERMS:
                assert term not in lower, f"Forbidden term '{term}' found in mission {mission.id}"

    # Also check docs/missions.md
    docs_path = Path("docs/missions.md")
    assert docs_path.is_file()
    content = docs_path.read_text(encoding="utf-8").lower()
    for m in MISSIONS:
        assert m.id in content, f"Mission id {m.id} not found in docs/missions.md"
    for term in _FORBIDDEN_TERMS:
        assert term not in content, f"Forbidden term '{term}' found in docs/missions.md"
