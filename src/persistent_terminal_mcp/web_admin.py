import asyncio
from collections import deque
import hmac
from ipaddress import ip_address
import re
import time
from typing import TypeVar

from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import JSONResponse

from .errors import ToolError
from .identity_store import Identities
from .security import private_file

ADMIN_ROUTES = ("/admin/connections", "/admin/agents", "/admin/tokens")
T = TypeVar("T", bound=BaseModel)


def admin_response(body: dict, status: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status, {
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", **(headers or {}),
    })


async def read_model(request: Request, model: type[T], limit: int = 32768) -> T:
    data = bytearray()
    if request.headers.get("content-encoding") not in {None, "identity"}:
        raise ToolError("INVALID_INPUT", "Compressed request bodies are not accepted.")
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise ToolError("BODY_TOO_LARGE", "Request body is too large.")
        data.extend(chunk)
    if data and request.headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
        raise ToolError("INVALID_INPUT", "Expected an application/json request.")
    return model.model_validate_json(data or b"{}")


class WebAdmin:
    def __init__(self, identities: Identities) -> None:
        self.identities = identities
        self.mutations: deque[float] = deque()

    async def authorize(self, request: Request) -> bool:
        file = self.identities.settings.web_admin_token_file
        authorization = request.headers.getlist("authorization")
        hosts = request.headers.getlist("host")
        if file is None or len(authorization) != 1 or not re.fullmatch(r"Bearer [0-9a-f]{64}", authorization[0]):
            return False
        if (request.client is None or "origin" in request.headers or len(hosts) != 1
                or not re.fullmatch(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?", hosts[0])):
            return False
        try:
            if not ip_address(request.client.host).is_loopback:
                return False
            expected = (await asyncio.to_thread(private_file, file)).strip()
        except (ValueError, OSError):
            return False
        supplied = authorization[0][7:]
        return (len(expected) == 64 and hmac.compare_digest(expected, supplied.encode())
                and not await self.identities.registered(supplied))

    def accept_token_mutation(self) -> int | None:
        now = time.monotonic()
        while self.mutations and now - self.mutations[0] >= 60:
            self.mutations.popleft()
        if len(self.mutations) >= self.identities.settings.admin_token_mutations_per_minute:
            return max(1, int(60 - (now - self.mutations[0])) + 1)
        self.mutations.append(now)
        return None
