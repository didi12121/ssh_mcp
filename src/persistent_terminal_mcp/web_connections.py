import asyncio
import hmac
from ipaddress import ip_address
import re

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Principal
from .errors import ToolError
from .models import ProfileInput, ProfilePatch
from .profiles import Profiles
from .security import MANAGED_PREFIX, Security, credential_id, private_file

ADMIN_OWNER = "dashboard"
ROUTE = "/admin/connections"


async def read_input(request: Request, patch: bool) -> ProfileInput | ProfilePatch:
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 8192:
            raise ToolError("INVALID_INPUT", "Connection request is too large.")
    return (ProfilePatch if patch else ProfileInput).model_validate_json(data)


def authorized(request: Request, security: Security) -> bool:
    file = security.settings.web_admin_token_file
    supplied = request.headers.get("authorization", "")
    if file is None or not re.fullmatch(r"Bearer [0-9a-f]{64}", supplied):
        return False
    if request.client is None or request.headers.get("origin"):
        return False
    try:
        if not ip_address(request.client.host).is_loopback or request.url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            return False
        expected = private_file(file).strip()
        return len(expected) == 64 and hmac.compare_digest(expected, supplied[7:].encode())
    except (ValueError, OSError):
        return False


def register_connection_routes(mcp: FastMCP, profiles: Profiles, security: Security) -> None:
    @mcp.custom_route(ROUTE, methods=["GET", "POST"])
    @mcp.custom_route(ROUTE + "/{profile_id}", methods=["PATCH", "DELETE"])
    @mcp.custom_route(ROUTE + "/{profile_id}/test", methods=["POST"])
    async def connections(request: Request) -> JSONResponse:
        if not await asyncio.to_thread(authorized, request, security):
            return JSONResponse({"code": "ADMIN_FORBIDDEN", "error": "Connection administration is unavailable."}, 403)

        try:
            configured = {agent.owner_id: agent for agent in security.principals()}
            selected = request.query_params.get("owner", ADMIN_OWNER)
            agent = configured.get(selected)
            if agent is None and selected != ADMIN_OWNER:
                raise ToolError("OWNER_NOT_FOUND", "The selected Agent no longer exists.")
            profile_id = request.path_params.get("profile_id")
            if profile_id and not re.fullmatch(r"[a-f0-9]{32}", profile_id):
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            dashboard = agent is None
            credential_types = {ref: item.kind for ref, item in security.credential_catalog().items()}
            directory = security.settings.managed_keys_dir
            if directory and directory.is_dir():
                for item in directory.iterdir():
                    if (item / "identity").is_file():
                        try:
                            ref = MANAGED_PREFIX + credential_id.validate_python(item.name)
                        except ValueError:
                            continue
                        credential_types.setdefault(ref, "key")
            if dashboard:
                # The UI-only owner has no bearer token. Scope this operation to the chosen profile.
                host = "localhost"
                if profile_id:
                    row = await profiles.store.profile(ADMIN_OWNER, profile_id)
                    host = row.configuration["host"]
                agent = Principal(owner_id=ADMIN_OWNER, token_sha256="0" * 64, targets=[host],
                                  credentials=set(credential_types))
            assert agent is not None

            if request.method == "GET":
                page = int(request.query_params.get("page", "1"))
                if not 1 <= page <= 100_000:
                    raise ToolError("INVALID_INPUT", "Invalid page number.")
                data = await profiles.list(agent, "", "", "", page, 25)
                return JSONResponse({
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
                data = await read_input(request, False)
                if dashboard:
                    agent.targets = [data.host]
                return JSONResponse(await profiles.create(agent, data), 201)
            if profile_id is None:
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            if request.method == "PATCH":
                changes = await read_input(request, True)
                if dashboard and changes.host is not None:
                    agent.targets = [ProfileInput.valid_host(changes.host.strip())]
                return JSONResponse(await profiles.edit(agent, profile_id, changes))
            if request.method == "DELETE":
                return JSONResponse(await profiles.delete(agent, profile_id))
            return JSONResponse(await profiles.test(agent, profile_id))
        except ToolError as failure:
            status = 404 if failure.code.endswith("_NOT_FOUND") else 409 if failure.code == "PROFILE_IN_USE" else 422
            return JSONResponse({"code": failure.code, "error": str(failure)}, status)
        except (ValidationError, ValueError):
            return JSONResponse({"code": "INVALID_INPUT", "error": "Invalid connection fields."}, 400)
        except OSError:
            return JSONResponse({"code": "ADMIN_UNAVAILABLE", "error": "Connection configuration is unavailable."}, 503)
