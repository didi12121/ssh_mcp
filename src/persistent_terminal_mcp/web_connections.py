import re

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Principal
from .errors import ToolError
from .identity_store import admin_audit
from .models import ProfileInput, ProfilePatch, Session
from .profiles import Profiles, profile_info
from .security import Security
from .sessions import Sessions
from .web_admin import WebAdmin, admin_response, read_model

ROUTE = "/admin/connections"
RESOURCE = re.compile(r"[a-f0-9]{32}")


def register_connection_routes(mcp: FastMCP, profiles: Profiles, sessions: Sessions, security: Security, admin: WebAdmin) -> None:
    @mcp.custom_route(ROUTE, methods=["GET", "POST"])
    @mcp.custom_route(ROUTE + "/{profile_id}", methods=["GET", "PATCH", "DELETE"])
    @mcp.custom_route(ROUTE + "/{profile_id}/test", methods=["POST"])
    @mcp.custom_route(ROUTE + "/{profile_id}/sessions", methods=["GET"])
    @mcp.custom_route(ROUTE + "/{profile_id}/sessions/{session_id}/close", methods=["POST"])
    async def connections(request: Request) -> JSONResponse:
        try:
            if not await admin.authorize(request):
                return admin_response({"code": "ADMIN_FORBIDDEN", "error": "Connection administration is unavailable."}, 403)
            profile_id = request.path_params.get("profile_id")
            if profile_id is None:
                if request.method == "POST":
                    return admin_response(await profiles.create(await read_model(request, ProfileInput, 8192)), 201)
                page = int(request.query_params.get("page", "1"))
                if not 1 <= page <= 100_000:
                    raise ValueError("Invalid page")
                data = await profiles.list("", "", "", page, 25)
                return admin_response({
                    **data,
                    "credentials": [
                        {"ref": ref, "auth_type": "password" if kind == "password" else "key"}
                        for ref, kind in sorted(security.visible_credentials().items())
                    ],
                    "ssh_agent": bool(security.settings.ssh_agent_path),
                })
            if not RESOURCE.fullmatch(profile_id):
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            if request.method == "PATCH":
                return admin_response(await profiles.edit(profile_id, await read_model(request, ProfilePatch, 8192)))
            if request.method == "DELETE":
                return admin_response(await profiles.delete(profile_id))
            session_id = request.path_params.get("session_id")
            if session_id:
                if not RESOURCE.fullmatch(session_id):
                    raise ToolError("SESSION_NOT_FOUND", "Terminal session not found.")
                async with profiles.store.transaction() as db:
                    row = await db.scalar(select(Session).where(
                        Session.session_id == session_id, Session.profile_id == profile_id,
                    ))
                if row is None:
                    raise ToolError("SESSION_NOT_FOUND", "Terminal session not found.")
                result = await sessions.close(Principal(owner_id=row.owner_id), row, False, admin=True)
                admin_audit("connection_session_close", profile_id=profile_id, session_id=session_id, owner_id=row.owner_id)
                return admin_response(result)
            if request.url.path.endswith("/sessions"):
                async with profiles.store.transaction() as db:
                    rows = (await db.scalars(select(Session).where(
                        Session.profile_id == profile_id, Session.status != "CLOSED",
                    ).order_by(Session.created_at))).all()
                return admin_response({"sessions": [sessions.describe(row) for row in rows]})
            if request.method == "GET":
                return admin_response(profile_info(await profiles.store.profile(profile_id)))
            return admin_response(await profiles.test(profile_id))
        except ToolError as failure:
            status = 404 if failure.code.endswith("_NOT_FOUND") else 409 if failure.code in {"PROFILE_IN_USE", "EXECUTION_ACTIVE"} else 422
            return admin_response({"code": failure.code, "error": str(failure)}, status)
        except (ValidationError, ValueError):
            return admin_response({"code": "INVALID_INPUT", "error": "Invalid connection fields."}, 400)
        except (OSError, SQLAlchemyError):
            return admin_response({"code": "ADMIN_UNAVAILABLE", "error": "Connection configuration is unavailable."}, 503)
