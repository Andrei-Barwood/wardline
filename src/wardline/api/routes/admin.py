from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from wardline.api.deps import LabState, require_role
from wardline.clients.identity import validate_client_id
from wardline.config.whitelist import (
    get_whitelisted_config,
    validate_config_patch,
)
from wardline.contracts import ErrorCode, Principal, Role
from wardline.errors import WardlineError

router = APIRouter()

AdminPrincipal = Annotated[Principal, Depends(require_role(Role.ADMIN))]


class BlockPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ttl_seconds: int | None = Field(default=None, ge=1, le=3600)


@router.get("/admin/config")
async def get_config(
    state: LabState,
    _: AdminPrincipal,
) -> dict[str, Any]:
    generation = state.config_history.current_generation()
    values = get_whitelisted_config(state.settings)
    return {"generation": generation, "values": values}


@router.post("/admin/config")
async def update_config(
    patch: dict[str, Any],
    state: LabState,
    _: AdminPrincipal,
) -> dict[str, Any]:
    validate_config_patch(patch)

    # Validate that updating settings with patch produces valid settings
    try:
        new_settings = state.settings.model_copy(update=patch)
    except Exception as caught:
        raise WardlineError(ErrorCode.validation_error, str(caught)) from caught

    # Take snapshot of current whitelisted values before applying
    current_snapshot = get_whitelisted_config(state.settings)
    state.config_history.push(current_snapshot)

    # Apply new settings
    state.replace_settings(new_settings)

    generation = state.config_history.current_generation()
    applied = {k: getattr(new_settings, k) for k in patch}
    return {"generation": generation, "applied": applied}


@router.post("/admin/recovery/rollback")
async def rollback_config(
    state: LabState,
    _: AdminPrincipal,
) -> dict[str, Any]:
    prev = state.config_history.previous()
    if prev is None:
        raise WardlineError(ErrorCode.invalid_state_transition, "no configuration to rollback")

    try:
        new_settings = state.settings.model_copy(update=prev)
    except Exception as caught:
        raise WardlineError(ErrorCode.validation_error, str(caught)) from caught

    state.replace_settings(new_settings)

    generation = state.config_history.current_generation()
    return {"generation": generation, "restored": prev}


@router.post("/admin/clients/{client_id}/block")
async def block_client(
    client_id: str,
    state: LabState,
    _: AdminPrincipal,
    payload: BlockPayload | None = None,
) -> dict[str, Any]:
    try:
        validated_client_id = validate_client_id(client_id)
    except WardlineError:
        raise WardlineError(ErrorCode.validation_error, "invalid client_id") from None

    ttl = (
        payload.ttl_seconds
        if (payload is not None and payload.ttl_seconds is not None)
        else state.settings.block_ttl_seconds
    )
    now = state.clock.now()
    until = now + timedelta(seconds=ttl)
    state.blocks.block(
        validated_client_id,
        until=until,
        reason="manual",
        incident_id="manual",
    )
    return {
        "client_id": validated_client_id,
        "blocked": True,
        "blocked_until": until.isoformat(),
    }


@router.post("/admin/clients/{client_id}/unblock")
async def unblock_client(
    client_id: str,
    state: LabState,
    _: AdminPrincipal,
) -> dict[str, Any]:
    try:
        validated_client_id = validate_client_id(client_id)
    except WardlineError:
        raise WardlineError(ErrorCode.validation_error, "invalid client_id") from None

    unblocked = state.blocks.unblock(validated_client_id)
    if not unblocked:
        raise WardlineError(ErrorCode.not_found, "client is not blocked")
    return {"status": "unblocked", "client_id": validated_client_id}
