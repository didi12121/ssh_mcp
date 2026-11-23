import re
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Identifier
from .errors import ToolError
from .identity_models import TOKEN_STATES, TokenInput, TokenPermissionPatch, TokenRevocation, TokenRotation
from .models import Profile
from .profiles import connection_alias
from .web_admin import WebAdmin, admin_response, read_model

identifier = TypeAdapter(Identifier)


def pagination(request: Request) -> tuple[int, int]:
    page = int(request.query_params.get("page", "1"))
    limit = int(request.query_params.get("limit", "25"))
    if not 1 <= page <= 100_000 or not 1 <= limit <= 100:
        raise ValueError("Invalid pagination")
    return page, limit


def request_key(request: Request) -> str | None:
    values = request.headers.getlist("idempotency-key")
    if not values:
        return None
    if len(values) != 1 or not re.fullmatch(r"[a-f0-9-]{36}", values[0]):
        raise ValueError("Invalid idempotency key")
    return str(UUID(values[0]))


def error_response(failure: Exception) -> JSONResponse:
    if isinstance(failure, ToolError):
        status = {
            "TOKEN_NOT_FOUND": 404, "TOKEN_INACTIVE": 409, "INVALID_PROFILE_GRANT": 422,
            "TOKEN_ALREADY_ISSUED": 409, "INVALID_EXPIRY": 422, "BODY_TOO_LARGE": 413,
        }.get(failure.code, 400)
        return admin_response({"code": failure.code, "error": str(failure)}, status)
    if isinstance(failure, (ValidationError, ValueError)):
        return admin_response({"code": "INVALID_INPUT", "error": "Invalid Token fields."}, 400)
    return admin_response({"code": "ADMIN_UNAVAILABLE", "error": "Identity storage is unavailable."}, 503)


def register_identity_routes(mcp: FastMCP, admin: WebAdmin) -> None:
    identities = admin.identities

    @mcp.custom_route("/admin/tokens", methods=["GET", "POST"])
    @mcp.custom_route("/admin/tokens/{token_id}", methods=["GET", "DELETE"])
    @mcp.custom_route("/admin/tokens/{token_id}/permissions", methods=["PATCH"])
    @mcp.custom_route("/admin/tokens/{token_id}/rotate", methods=["POST"])
    @mcp.custom_route("/admin/tokens/{token_id}/revoke", methods=["POST"])
    async def tokens(request: Request) -> JSONResponse:
        try:
            if not await admin.authorize(request):
                return admin_response({"code": "ADMIN_FORBIDDEN", "error": "Administrator authorization is required."}, 403)
            if request.method != "GET":
                retry = admin.accept_token_mutation()
                if retry is not None:
                    return admin_response({"code": "RATE_LIMITED", "error": "Too many token changes."},
                                          429, {"Retry-After": str(retry)})
            token_id = request.path_params.get("token_id")
            if token_id is None:
                if request.method == "POST":
                    return admin_response(await identities.create_token(
                        await read_model(request, TokenInput), request_key(request),
                    ), 201)
                page, limit = pagination(request)
                owner = request.query_params.get("owner")
                status = request.query_params.get("status")
                if owner is not None:
                    owner = identifier.validate_python(owner)
                if status is not None and status not in TOKEN_STATES:
                    raise ValueError("Invalid token status")
                payload = await identities.tokens(owner, status, page, limit)
                if request.query_params.get("catalog") == "1":
                    async with identities.store.transaction() as db:
                        available = (await db.scalars(select(Profile).where(Profile.deleted_at.is_(None))
                                                      .order_by(Profile.profile_id))).all()
                    payload["catalog"] = [{**connection_alias(row), "enabled": row.enabled} for row in available]
                return admin_response(payload)
            if not re.fullmatch(r"[a-f0-9]{32}", token_id):
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if request.method == "GET":
                return admin_response(await identities.token(token_id))
            if request.method == "DELETE":
                return admin_response(await identities.revoke(token_id, "deleted", delete_record=True))
            if request.method == "PATCH":
                return admin_response(await identities.update_permissions(token_id, await read_model(request, TokenPermissionPatch)))
            if request.url.path.endswith("/rotate"):
                return admin_response(await identities.rotate(
                    token_id, request_key(request), await read_model(request, TokenRotation, 4096),
                ), 201)
            data = await read_model(request, TokenRevocation, 4096)
            return admin_response(await identities.revoke(token_id, data.reason))
        except (ToolError, ValidationError, ValueError, OSError, SQLAlchemyError) as failure:
            return error_response(failure)
