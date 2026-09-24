from typing import Annotated, Any

from fastapi import APIRouter, Depends

from wardline.api.deps import LabState, require_role
from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode, Principal, Role
from wardline.errors import WardlineError

router = APIRouter()

AdminPrincipal = Annotated[Principal, Depends(require_role(Role.ADMIN))]


@router.post("/admin/clients/{client_id}/unblock")
async def unblock_client(
    client_id: str,
    state: LabState,
    _: AdminPrincipal,
) -> dict[str, Any]:
    validated_client_id = validate_client_id(client_id)
    unblocked = state.blocks.unblock(validated_client_id)
    if not unblocked:
        raise WardlineError(ErrorCode.not_found, "client is not blocked")
    return {"status": "unblocked", "client_id": validated_client_id}
