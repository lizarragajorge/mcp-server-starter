import asyncio
import ssl
from typing import Any

import jwt
import truststore
from mcp.server.auth.provider import AccessToken
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from catalog.config import Settings
from catalog.operational import logger


class SigningKeysUnavailable(RuntimeError):
    pass


class SigningKeyAvailability:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await self.app(scope, receive, send)
        except SigningKeysUnavailable:
            await JSONResponse(
                {
                    "error": "auth_unavailable",
                    "detail": "Authentication signing keys are unavailable.",
                },
                status_code=503,
                headers={"Retry-After": "5"},
            )(scope, receive, send)


class EntraTokenVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.jwks = jwt.PyJWKClient(
            f"https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys",
            timeout=5,
            lifespan=300,
            ssl_context=truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        )

    def _decode(self, token: str) -> dict[str, Any]:
        key = self.jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            audience=self.settings.audience,
            issuer=self.settings.issuer,
            options={
                "require": ["exp", "iat", "nbf", "aud", "iss", "tid", "sub", "ver", "azp"],
                "strict_aud": True,
            },
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if len(token) > 16 * 1024:
            logger.warning(
                "oversized", extra={"event": "auth_rejected", "outcome": "invalid_token"}
            )
            return None
        try:
            claims = await asyncio.to_thread(self._decode, token)
        except jwt.PyJWKClientConnectionError:
            logger.error("jwks_unavailable", extra={"event": "auth_unavailable"})
            raise SigningKeysUnavailable from None
        except jwt.PyJWTError:
            logger.warning("invalid", extra={"event": "auth_rejected", "outcome": "invalid_token"})
            return None
        if (
            claims["tid"] != self.settings.tenant_id
            or claims["ver"] != "2.0"
            or not isinstance(claims["azp"], str)
            or not claims["azp"]
            or not isinstance(claims.get("scp", ""), str)
        ):
            logger.warning("claims", extra={"event": "auth_rejected", "outcome": "invalid_claims"})
            return None
        # Entra v2 access tokens use the API's application UUID as aud, not its HTTPS URL.
        return AccessToken(
            token=token,
            client_id=claims["azp"],
            subject=claims["sub"],
            scopes=[
                f"api://{self.settings.audience}/{scope}" for scope in claims.get("scp", "").split()
            ],
            expires_at=claims["exp"],
            resource=self.settings.audience,
        )
