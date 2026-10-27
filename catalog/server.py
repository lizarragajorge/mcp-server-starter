import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from catalog.config import Settings
from catalog.data import CATALOG, Character, CharacterList
from catalog.entra import EntraTokenVerifier, SigningKeyAvailability
from catalog.operational import configure_logging, logger

CatalogText = Annotated[str, Field(strict=True, min_length=1, max_length=100)]


def normalized(value: str, tool: str) -> str:
    result = value.strip().casefold()
    if not result:
        logger.info(
            "invalid_input", extra={"event": "tool_call", "tool": tool, "outcome": "invalid"}
        )
        raise ToolError("INVALID_INPUT: supply a non-blank string of at most 100 characters.")
    return result


def create_mcp(
    settings: Settings | None = None, token_verifier: TokenVerifier | None = None
) -> MCPServer:
    if settings is not None and settings.auth_mode == "broker" and token_verifier is None:
        raise ValueError("Broker mode requires the broker token verifier.")
    oauth = settings is not None and settings.auth_mode in ("entra", "broker")
    mcp = MCPServer(
        "Workshop Character Catalog",
        version="0.1.0",
        instructions="Use these tools for catalog facts; report errors, never guess.",
        token_verifier=(
            token_verifier or EntraTokenVerifier(settings) if oauth and settings else None
        ),
        auth=(
            AuthSettings(
                issuer_url=AnyHttpUrl(
                    settings.resource_url.removesuffix("/mcp")
                    if settings.auth_mode == "broker"
                    else settings.issuer
                ),
                resource_server_url=AnyHttpUrl(settings.resource_url),
                required_scopes=[settings.delegated_scope],
                validate_token_resource=False,
            )
            if oauth and settings
            else None
        ),
    )
    read_only = ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )

    @mcp.tool(annotations=read_only)
    def list_characters(affiliation: CatalogText | None = None) -> CharacterList:
        """List bundled catalog characters, optionally by exact case-insensitive affiliation.

        Trim surrounding whitespace. Omit affiliation (or use null) for all characters.
        Unknown affiliations succeed with characters=[] and count=0. Blank strings are invalid.
        """
        match = normalized(affiliation, "list_characters") if affiliation is not None else None
        characters = [c for c in CATALOG if match is None or c.affiliation.casefold() == match]
        logger.info(
            "listed",
            extra={
                "event": "tool_call",
                "tool": "list_characters",
                "outcome": "success",
                "count": len(characters),
            },
        )
        return CharacterList(characters=characters, count=len(characters))

    @mcp.tool(annotations=read_only)
    def get_character(name: CatalogText) -> Character:
        """Get one bundled character by exact case-insensitive name, trimming outer whitespace.

        Returns name, homeworld and affiliation. NOT_FOUND is a tool error, not a fact.
        Blank/non-string/overlong names are invalid; do not substitute general knowledge.
        """
        match = normalized(name, "get_character")
        for character in CATALOG:
            if character.name.casefold() == match:
                logger.info(
                    "found",
                    extra={"event": "tool_call", "tool": "get_character", "outcome": "success"},
                )
                return character
        logger.info(
            "not_found",
            extra={"event": "tool_call", "tool": "get_character", "outcome": "not_found"},
        )
        raise ToolError("NOT_FOUND: no character with that name is in the bundled catalog.")

    return mcp


class RequestGate:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.key = settings.api_key.encode("ascii")
        self.header = settings.header.lower().encode("ascii")
        self.api_key_mode = settings.auth_mode == "api_key"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = perf_counter()
        status = 500

        async def observed_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            if self.api_key_mode and scope["path"] != "/health":
                values = [v for k, v in scope["headers"] if k.lower() == self.header]
                if len(values) != 1 or not hmac.compare_digest(values[0], self.key):
                    await JSONResponse({"error": "unauthorized"}, status_code=401)(
                        scope, receive, observed_send
                    )
                    return
            await self.app(scope, receive, observed_send)
        finally:
            logger.info(
                "request",
                extra={
                    "event": "http_request",
                    "status": status,
                    "duration_ms": round((perf_counter() - start) * 1000, 2),
                },
            )


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def create_app() -> ASGIApp:
    configure_logging()
    settings = Settings.from_env()
    broker = None
    oauth_routes = []
    if settings.auth_mode == "broker":
        from catalog.broker import Broker

        broker = Broker(settings)
        oauth_routes = broker.provider.get_routes(mcp_path="/mcp")
    mcp = create_mcp(settings, broker)
    allowed_hosts = [entry for host in settings.hosts for entry in (host, f"{host}:*")]
    origins = [
        entry
        for host in settings.hosts
        for scheme in (
            ("http", "https") if host in ("localhost", "127.0.0.1", "[::1]") else ("https",)
        )
        for entry in (f"{scheme}://{host}", f"{scheme}://{host}:*")
    ]
    mcp_app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=64 * 1024,
        transport_security=TransportSecuritySettings(
            allowed_hosts=allowed_hosts, allowed_origins=origins
        ),
    )
    if settings.auth_mode in ("entra", "broker"):
        mcp_app.add_middleware(SigningKeyAvailability)
    if broker is not None:
        from catalog.broker import BrokerStateAvailability

        mcp_app.add_middleware(BrokerStateAvailability)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        try:
            async with mcp.session_manager.run():
                logger.info("startup", extra={"event": "startup"})
                yield
        finally:
            if broker is not None:
                await broker.close()

    app = Starlette(
        routes=[Route("/health", health), *oauth_routes, Mount("/", app=mcp_app)],
        lifespan=lifespan,
    )
    if broker is not None:
        from catalog.broker import BrokerStateAvailability, RegistrationGuard

        app.add_middleware(BrokerStateAvailability)
        app.add_middleware(SigningKeyAvailability)
        app.add_middleware(RegistrationGuard)
    configure_logging()
    return RequestGate(app, settings)
