from collections import deque
from time import monotonic

from azure.core.exceptions import AzureError
from azure.data.tables.aio import TableClient
from azure.identity.aio import ManagedIdentityCredential
from cryptography.fernet import Fernet
from fastmcp.server.auth import AccessToken, OAuthProxy, TokenVerifier
from key_value.aio.errors import DecryptionError, KeyValueOperationError, KeyValueStoreError
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.azure_tables import AzureTablesSanitizationStrategy, AzureTablesStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from catalog.config import Settings
from catalog.entra import EntraTokenVerifier
from catalog.operational import logger


class UpstreamVerifier(TokenVerifier):
    def __init__(self, settings: Settings) -> None:
        super().__init__(required_scopes=[settings.delegated_scope])
        self.verifier = EntraTokenVerifier(settings)

    async def verify_token(self, token: str) -> AccessToken | None:
        result = await self.verifier.verify_token(token)
        if result is None or not set(self.required_scopes).issubset(result.scopes):
            return None
        return AccessToken.model_validate({**result.model_dump(), "claims": result.claims or {}})


class Broker:
    def __init__(self, settings: Settings, storage: AsyncKeyValue | None = None) -> None:
        self.credential: ManagedIdentityCredential | None = None
        self.table: TableClient | None = None
        if storage is None:
            self.credential = ManagedIdentityCredential(
                client_id=settings.broker_identity_client_id or None
            )
            self.table = TableClient(
                endpoint=settings.broker_table_endpoint,
                table_name="oauthstate",
                credential=self.credential,
            )
            storage = AzureTablesStore(
                client=self.table,
                auto_create=False,
                key_sanitization_strategy=AzureTablesSanitizationStrategy(),
                collection_sanitization_strategy=AzureTablesSanitizationStrategy(),
            )
        self.storage = FernetEncryptionWrapper(
            key_value=storage, fernet=Fernet(settings.broker_encryption_key.encode("ascii"))
        )
        origin = settings.resource_url.removesuffix("/mcp")
        authority = f"https://login.microsoftonline.com/{settings.tenant_id}/oauth2/v2.0"
        self.provider = OAuthProxy(
            upstream_authorization_endpoint=authority + "/authorize",
            upstream_token_endpoint=authority + "/token",
            upstream_client_id=settings.broker_client_id,
            upstream_client_secret=settings.broker_client_secret,
            token_verifier=UpstreamVerifier(settings),
            base_url=origin,
            resource_base_url=origin,
            issuer_url=origin,
            redirect_path="/auth/callback",
            allowed_client_redirect_uris=list(settings.broker_redirect_uris),
            valid_scopes=[settings.delegated_scope],
            extra_authorize_params={"scope": settings.delegated_scope + " offline_access"},
            forward_pkce=True,
            forward_resource=False,
            token_endpoint_auth_method="client_secret_post",
            client_storage=self.storage,
            jwt_signing_key=settings.broker_signing_key.encode("ascii"),
            require_authorization_consent=True,
            enable_cimd=False,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        # Check state availability outside the library's invalid-token handling.
        await self.storage.get(key="availability", collection="health")
        result = await self.provider.verify_token(token)
        if result is None:
            logger.warning(
                "broker_token_rejected", extra={"event": "auth_rejected", "outcome": "invalid"}
            )
        return result

    async def close(self) -> None:
        if self.table is not None:
            await self.table.close()
        if self.credential is not None:
            await self.credential.close()


class BrokerStateAvailability:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await self.app(scope, receive, send)
        except (AzureError, KeyValueStoreError, KeyValueOperationError, DecryptionError):
            logger.error("oauth_storage_unavailable", extra={"event": "auth_unavailable"})
            await JSONResponse(
                {"error": "auth_unavailable", "detail": "OAuth state storage is unavailable."},
                status_code=503,
                headers={"Retry-After": "5"},
            )(scope, receive, send)


class RegistrationGuard:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.registrations: deque[float] = deque()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != "/register" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        now = monotonic()
        while self.registrations and self.registrations[0] <= now - 60:
            self.registrations.popleft()
        if len(self.registrations) >= 60:
            await JSONResponse(
                {"error": "registration_rate_limited"},
                status_code=429,
                headers={"Retry-After": "60"},
            )(scope, receive, send)
            return
        self.registrations.append(now)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 16 * 1024:
                await JSONResponse({"error": "registration_too_large"}, status_code=413)(
                    scope, receive, send
                )
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, bounded_receive, send)
