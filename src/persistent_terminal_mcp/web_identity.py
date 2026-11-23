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
from .identity_models import AgentInput, AgentPatch, TOKEN_STATES, TokenInput, TokenRevocation
from .models import Profile
from .security import Security
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
            "AGENT_NOT_FOUND": 404, "TOKEN_NOT_FOUND": 404, "AGENT_EXISTS": 409, "TOKEN_INACTIVE": 409,
            "TOKEN_ALREADY_ISSUED": 409, "INVALID_EXPIRY": 422, "BODY_TOO_LARGE": 413,
        }.get(failure.code, 400)
        return admin_response({"code": failure.code, "error": str(failure)}, status)
    if isinstance(failure, (ValidationError, ValueError)):
        return admin_response({"code": "INVALID_INPUT", "error": "Invalid Agent or token fields."}, 400)
    return admin_response({"code": "ADMIN_UNAVAILABLE", "error": "Identity storage is unavailable."}, 503)


def register_identity_routes(mcp: FastMCP, admin: WebAdmin, security: Security) -> None:
    identities = admin.identities

    @mcp.custom_route("/admin/agents", methods=["GET", "POST"])
    @mcp.custom_route("/admin/agents/{owner_id}", methods=["GET", "PATCH"])
    async def agents(request: Request) -> JSONResponse:
        try:
            if not await admin.authorize(request):
                return admin_response({"code": "ADMIN_FORBIDDEN", "error": "Administrator authorization is required."}, 403)
            owner = request.path_params.get("owner_id")
            if owner is not None:
                owner = identifier.validate_python(owner)
                if request.method == "GET":
                    return admin_response(await identities.agent(owner))
                return admin_response(await identities.update_agent(owner, await read_model(request, AgentPatch)))
            if request.method == "POST":
                return admin_response(await identities.create_agent(await read_model(request, AgentInput)), 201)
            page, limit = pagination(request)
            search = request.query_params.get("search", "")
            if len(search) > 100:
                raise ValueError("Search is too long")
            payload = await identities.agents(page, limit, search)
            if request.query_params.get("catalog") == "1":
                async with identities.store.transaction() as db:
                    host = Profile.configuration["host"].as_string()
                    targets = (await db.scalars(select(host).distinct().order_by(host).limit(1000))).all()
                payload["targets"] = [target for target in targets if target]
                payload["credentials"] = [
                    {"ref": ref, "kind": kind} for ref, kind in sorted(security.visible_credentials().items())
                ]
            return admin_response(payload)
        except (ToolError, ValidationError, ValueError, OSError, SQLAlchemyError) as failure:
            return error_response(failure)

    @mcp.custom_route("/admin/tokens", methods=["GET", "POST"])
    @mcp.custom_route("/admin/tokens/{token_id}", methods=["GET", "DELETE"])
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
                        await read_model(request, TokenInput, 4096), request_key(request),
                    ), 201)
                page, limit = pagination(request)
                owner = request.query_params.get("owner")
                status = request.query_params.get("status")
                if owner is not None:
                    owner = identifier.validate_python(owner)
                if status is not None and status not in TOKEN_STATES:
                    raise ValueError("Invalid token status")
                return admin_response(await identities.tokens(owner, status, page, limit))
            if not re.fullmatch(r"[a-f0-9]{32}", token_id):
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if request.method == "GET":
                return admin_response(await identities.token(token_id))
            if request.method == "DELETE":
                return admin_response(await identities.revoke(token_id, "deleted", delete=True))
            if request.url.path.endswith("/rotate"):
                return admin_response(await identities.rotate(token_id, request_key(request)), 201)
            data = await read_model(request, TokenRevocation, 4096)
            return admin_response(await identities.revoke(token_id, data.reason))
        except (ToolError, ValidationError, ValueError, OSError, SQLAlchemyError) as failure:
            return error_response(failure)
