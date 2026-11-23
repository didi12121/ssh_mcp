import re

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Principal
from .errors import ToolError
from .models import ProfileInput, ProfilePatch
from .profiles import Profiles
from .security import Security
from .web_admin import WebAdmin, admin_response, read_model

ADMIN_OWNER = "dashboard"
ROUTE = "/admin/connections"


def register_connection_routes(mcp: FastMCP, profiles: Profiles, security: Security, admin: WebAdmin) -> None:
    @mcp.custom_route(ROUTE, methods=["GET", "POST"])
    @mcp.custom_route(ROUTE + "/{profile_id}", methods=["PATCH", "DELETE"])
    @mcp.custom_route(ROUTE + "/{profile_id}/test", methods=["POST"])
    async def connections(request: Request) -> JSONResponse:
        try:
            if not await admin.authorize(request):
                return admin_response({"code": "ADMIN_FORBIDDEN", "error": "Connection administration is unavailable."}, 403)
            configured = await admin.identities.principals()
            selected = request.query_params.get("owner", ADMIN_OWNER)
            agent = configured.get(selected)
            if agent is None and selected != ADMIN_OWNER:
                raise ToolError("OWNER_NOT_FOUND", "The selected Agent no longer exists.")
            profile_id = request.path_params.get("profile_id")
            if profile_id and not re.fullmatch(r"[a-f0-9]{32}", profile_id):
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            dashboard = agent is None
            credential_types = security.visible_credentials()
            if dashboard:
                # The UI-only owner has no bearer token. Scope this operation to the chosen profile.
                host = "localhost"
                if profile_id:
                    row = await profiles.store.profile(ADMIN_OWNER, profile_id)
                    host = row.configuration["host"]
                agent = Principal(owner_id=ADMIN_OWNER, targets=[host], credentials=set(credential_types))
            assert agent is not None

            if request.method == "GET":
                page = int(request.query_params.get("page", "1"))
                if not 1 <= page <= 100_000:
                    raise ToolError("INVALID_INPUT", "Invalid page number.")
                data = await profiles.list(agent, "", "", "", page, 25)
                return admin_response({
                    **data, "owners": sorted({ADMIN_OWNER, *configured}), "owner": selected,
                    "allowed_targets": [] if dashboard else agent.targets,
                    "credentials": [
                        {"ref": ref, "auth_type": "password" if kind == "password" else "key"}
                        for ref, kind in sorted(credential_types.items())
                        if ref in agent.credentials
                    ],
                    "ssh_agent": agent.ssh_agent and bool(security.settings.ssh_agent_path),
                })
            if request.method == "POST" and profile_id is None:
                data = await read_model(request, ProfileInput, 8192)
                if dashboard:
                    agent.targets = [data.host]
                return admin_response(await profiles.create(agent, data), 201)
            if profile_id is None:
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            if request.method == "PATCH":
                changes = await read_model(request, ProfilePatch, 8192)
                if dashboard and changes.host is not None:
                    agent.targets = [ProfileInput.valid_host(changes.host.strip())]
                return admin_response(await profiles.edit(agent, profile_id, changes))
            if request.method == "DELETE":
                return admin_response(await profiles.delete(agent, profile_id))
            return admin_response(await profiles.test(agent, profile_id))
        except ToolError as failure:
            status = 404 if failure.code.endswith("_NOT_FOUND") else 409 if failure.code == "PROFILE_IN_USE" else 422
            return admin_response({"code": failure.code, "error": str(failure)}, status)
        except (ValidationError, ValueError):
            return admin_response({"code": "INVALID_INPUT", "error": "Invalid connection fields."}, 400)
        except (OSError, SQLAlchemyError):
            return admin_response({"code": "ADMIN_UNAVAILABLE", "error": "Connection configuration is unavailable."}, 503)
