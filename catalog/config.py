import os
import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.fernet import Fernet

ENTRA_SCOPE = "Catalog.Read"


@dataclass(frozen=True)
class Settings:
    api_key: str
    header: str
    hosts: tuple[str, ...]
    auth_mode: Literal["api_key", "entra", "broker"] = "api_key"
    tenant_id: str = ""
    audience: str = ""
    resource_url: str = ""
    broker_client_id: str = ""
    broker_client_secret: str = field(default="", repr=False)
    broker_signing_key: str = field(default="", repr=False)
    broker_encryption_key: str = field(default="", repr=False)
    broker_table_endpoint: str = ""
    broker_identity_client_id: str = ""
    broker_redirect_uris: tuple[str, ...] = ()

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def delegated_scope(self) -> str:
        return f"api://{self.audience}/{ENTRA_SCOPE}"

    @classmethod
    def from_env(cls, *, for_deployment: bool = False) -> "Settings":
        mode = os.environ.get("MCP_AUTH_MODE", "api_key")
        if mode not in ("api_key", "entra", "broker"):
            raise ValueError(
                "MCP_AUTH_MODE must be api_key, entra or broker; anonymous mode is unsupported."
            )
        key = os.environ.get("MCP_API_KEY", "")
        if mode == "api_key" and (
            len(key) < 32
            or not key.isascii()
            or any(c.isspace() for c in key)
            or key.lower().startswith(("replace", "placeholder", "change"))
        ):
            raise ValueError(
                "MCP_API_KEY must be a generated ASCII secret of at least 32 characters, "
                "without whitespace; placeholders are rejected."
            )
        header = os.environ.get("MCP_API_KEY_HEADER", "X-API-Key")
        if not re.fullmatch(r"X-[A-Za-z0-9-]+", header, flags=re.IGNORECASE):
            raise ValueError("MCP_API_KEY_HEADER must be a custom X- header name.")
        if header.lower().startswith(("x-forwarded-", "x-ms-")):
            raise ValueError("MCP_API_KEY_HEADER must not use proxy or platform-reserved headers.")
        hosts = tuple(
            h.strip().lower()
            for h in os.environ.get("MCP_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
        )
        for host in hosts:
            try:
                ip_address(host.strip("[]"))
            except ValueError:
                if len(host) > 253 or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split(".")
                ):
                    raise ValueError(
                        "MCP_ALLOWED_HOSTS requires exact hostnames, not URLs/wildcards."
                    ) from None
        tenant_id = os.environ.get("MCP_ENTRA_TENANT_ID", "")
        audience = os.environ.get("MCP_ENTRA_AUDIENCE", "")
        resource_url = os.environ.get("MCP_RESOURCE_URL", "")
        if mode in ("entra", "broker"):
            for name, value in (
                ("MCP_ENTRA_TENANT_ID", tenant_id),
                ("MCP_ENTRA_AUDIENCE", audience),
            ):
                try:
                    if str(UUID(value)) != value:
                        raise ValueError("not a canonical UUID")
                except ValueError:
                    raise ValueError(
                        f"{name} must be a lowercase tenant/application UUID."
                    ) from None
            if resource_url or not for_deployment:
                resource = urlsplit(resource_url)
                if (
                    resource.scheme not in ("http", "https")
                    or resource.hostname not in hosts
                    or resource.username
                    or resource.password
                    or resource.query
                    or resource.fragment
                    or resource.path != "/mcp"
                    or (
                        resource.scheme == "http"
                        and resource.hostname not in ("localhost", "127.0.0.1", "::1")
                    )
                ):
                    raise ValueError(
                        "MCP_RESOURCE_URL must be an allowed HTTPS hostname ending in /mcp "
                        "(HTTP is allowed only for local loopback tests)."
                    )
        broker_client_id = os.environ.get("MCP_BROKER_CLIENT_ID", "")
        broker_client_secret = os.environ.get("MCP_BROKER_CLIENT_SECRET", "")
        broker_signing_key = os.environ.get("MCP_BROKER_SIGNING_KEY", "")
        broker_encryption_key = os.environ.get("MCP_BROKER_ENCRYPTION_KEY", "")
        broker_table_endpoint = os.environ.get("MCP_BROKER_TABLE_ENDPOINT", "")
        broker_identity_client_id = os.environ.get("MCP_BROKER_IDENTITY_CLIENT_ID", "")
        broker_redirect_uris = tuple(
            value.strip()
            for value in os.environ.get(
                "MCP_BROKER_REDIRECT_URIS",
                "https://global.consent.azure-apim.net/redirect,"
                "https://global.consent.azure-apim.net/redirect/*",
            ).split(",")
        )
        if mode == "broker":
            try:
                if str(UUID(broker_client_id)) != broker_client_id:
                    raise ValueError("not canonical")
            except ValueError:
                raise ValueError("MCP_BROKER_CLIENT_ID must be an application UUID.") from None
            for name, value, minimum in (
                ("MCP_BROKER_CLIENT_SECRET", broker_client_secret, 16),
                ("MCP_BROKER_SIGNING_KEY", broker_signing_key, 43),
            ):
                if len(value) < minimum or not value.isascii() or any(c.isspace() for c in value):
                    raise ValueError(f"{name} must be a nonempty high-entropy ASCII secret.")
            try:
                Fernet(broker_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError):
                raise ValueError("MCP_BROKER_ENCRYPTION_KEY must be a Fernet key.") from None
            if (broker_table_endpoint or not for_deployment) and not re.fullmatch(
                r"https://[a-z0-9]{3,24}\.table\.core\.windows\.net/?",
                broker_table_endpoint,
            ):
                raise ValueError("MCP_BROKER_TABLE_ENDPOINT must be an Azure Tables HTTPS URL.")
            for uri in broker_redirect_uris:
                redirect = urlsplit(uri)
                if (
                    redirect.scheme != "https"
                    or not redirect.hostname
                    or redirect.username
                    or redirect.password
                    or redirect.query
                    or redirect.fragment
                    or "*" in redirect.netloc
                    or "*" in uri.rstrip("*")
                ):
                    raise ValueError(
                        "MCP_BROKER_REDIRECT_URIS requires HTTPS URLs; "
                        "only a trailing path wildcard is allowed."
                    )
        return cls(
            api_key=key if mode == "api_key" else "",
            header=header,
            hosts=hosts,
            auth_mode=mode,
            tenant_id=tenant_id,
            audience=audience,
            resource_url=resource_url,
            broker_client_id=broker_client_id,
            broker_client_secret=broker_client_secret,
            broker_signing_key=broker_signing_key,
            broker_encryption_key=broker_encryption_key,
            broker_table_endpoint=broker_table_endpoint,
            broker_identity_client_id=broker_identity_client_id,
            broker_redirect_uris=broker_redirect_uris,
        )
