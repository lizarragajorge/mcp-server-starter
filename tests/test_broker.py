import asyncio
import base64
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from azure.core.exceptions import ServiceRequestError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from key_value.aio.errors import StoreSetupError
from key_value.aio.stores.memory import MemoryStore
from starlette.testclient import TestClient
from test_entra import AUDIENCE, CLIENT, TENANT, token

from catalog.broker import Broker
from catalog.config import Settings
from catalog.server import create_app
from scripts import deploy

CALLBACK = "https://global.consent.azure-apim.net/redirect/test-connector"
RESOURCE = "https://catalog.example/mcp"


@pytest.fixture
def broker_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    for name, value in {
        "MCP_AUTH_MODE": "broker",
        "MCP_ENTRA_TENANT_ID": TENANT,
        "MCP_ENTRA_AUDIENCE": AUDIENCE,
        "MCP_RESOURCE_URL": RESOURCE,
        "MCP_ALLOWED_HOSTS": "catalog.example",
        "MCP_BROKER_CLIENT_ID": CLIENT,
        "MCP_BROKER_CLIENT_SECRET": "synthetic-client-secret-" + "x" * 32,
        "MCP_BROKER_SIGNING_KEY": "synthetic-signing-secret-" + "y" * 43,
        "MCP_BROKER_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "MCP_BROKER_TABLE_ENDPOINT": "https://synthetic.table.core.windows.net",
    }.items():
        monkeypatch.setenv(name, value)
    return Settings.from_env()


def register(http: TestClient, scope: str) -> str:
    response = http.post(
        "/register",
        json={
            "client_name": "Synthetic Copilot client",
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": scope,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def authorize(http: TestClient, client_id: str, scope: str) -> str:
    verifier = "synthetic-pkce-verifier-" + "x" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    response = http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "scope": scope,
            "state": "synthetic-client-state",
            "resource": RESOURCE,
            "code_challenge": challenge.decode().rstrip("="),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    consent = http.get(response.headers["location"])
    assert consent.status_code == 200
    fields = dict(re.findall(r'name="([^"]+)"\s+value="([^"]*)"', consent.text))
    assert "csrf_token" in fields and "txn_id" in fields
    approved = http.post("/consent", data={**fields, "action": "approve"}, follow_redirects=False)
    assert approved.status_code == 302, approved.text
    upstream = urlsplit(approved.headers["location"])
    assert upstream.hostname == "login.microsoftonline.com"
    query = parse_qs(upstream.query)
    assert query["client_id"] == [CLIENT]
    assert query["redirect_uri"] == ["https://catalog.example/auth/callback"]
    assert query["scope"] == [scope + " offline_access"]
    assert query["code_challenge_method"] == ["S256"]
    assert "resource" not in query
    callback = http.get(
        "/auth/callback",
        params={"code": "synthetic-entra-code", "state": query["state"][0]},
        follow_redirects=False,
    )
    assert callback.status_code == 302, callback.text
    redirected = urlsplit(callback.headers["location"])
    assert redirected.scheme + "://" + redirected.netloc + redirected.path == CALLBACK
    result = parse_qs(redirected.query)
    assert result["state"] == ["synthetic-client-state"]
    return result["code"][0]


def test_discovery_registration_and_encrypted_persistence(broker_settings: Settings) -> None:
    raw = MemoryStore()
    broker = Broker(broker_settings, raw)
    with patch("catalog.broker.Broker", return_value=broker):
        with TestClient(create_app(), base_url="https://catalog.example") as http:
            metadata = http.get("/.well-known/oauth-protected-resource/mcp").json()
            assert metadata["resource"] == RESOURCE
            assert metadata["authorization_servers"] == ["https://catalog.example/"]
            discovery = http.get("/.well-known/oauth-authorization-server").json()
            assert discovery["registration_endpoint"] == "https://catalog.example/register"
            assert discovery["code_challenge_methods_supported"] == ["S256"]
            client_id = register(http, broker_settings.delegated_scope)
            assert http.post("/mcp").status_code == 401
            assert http.post("/mcp", headers={"Authorization": "Bearer invalid"}).status_code == 401

    restarted = Broker(broker_settings, raw)
    assert asyncio.run(restarted.provider.get_client(client_id)) is not None
    asyncio.run(broker.storage.put(key="test", collection="test", value={"secret": "synthetic"}))
    assert "synthetic" not in json.dumps(asyncio.run(raw.get(key="test", collection="test")))
    assert asyncio.run(restarted.storage.get(key="test", collection="test")) == {
        "secret": "synthetic"
    }


def test_complete_pkce_flow_and_tool_call(broker_settings: Settings) -> None:
    broker = Broker(broker_settings, MemoryStore())
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    upstream = {
        "access_token": token(signing_key),
        "refresh_token": "synthetic-upstream-refresh",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": broker_settings.delegated_scope,
    }
    original = broker.provider._create_upstream_oauth_client

    def upstream_client():
        client = original()
        client.fetch_token = AsyncMock(return_value=upstream)
        client.refresh_token = AsyncMock(return_value=upstream)
        return client

    with (
        patch("catalog.broker.Broker", return_value=broker),
        patch.object(broker.provider, "_create_upstream_oauth_client", side_effect=upstream_client),
        patch(
            "jwt.PyJWKClient.get_signing_key_from_jwt",
            return_value=SimpleNamespace(key=signing_key.public_key()),
        ),
        TestClient(create_app(), base_url="https://catalog.example") as http,
    ):
        client_id = register(http, broker_settings.delegated_scope)
        code = authorize(http, client_id, broker_settings.delegated_scope)
        form = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": CALLBACK,
            "code_verifier": "synthetic-pkce-verifier-" + "x" * 43,
            "resource": RESOURCE,
        }
        wrong_pkce = http.post("/token", data={**form, "code_verifier": "wrong-" + "x" * 50})
        assert wrong_pkce.status_code in (400, 401)
        form["code"] = authorize(http, client_id, broker_settings.delegated_scope)
        issued = http.post("/token", data=form)
        assert issued.status_code == 200, issued.text
        access = issued.json()["access_token"]
        assert access != upstream["access_token"]
        assert http.post("/token", data=form).status_code in (400, 401)
        result = http.post(
            "/mcp",
            headers={
                "Authorization": "Bearer " + access,
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-11-25",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_characters", "arguments": {}},
            },
        )
        assert result.status_code == 200, result.text
        assert result.json()["result"]["structuredContent"]["count"] == 4
        claims = jwt.decode(access, options={"verify_signature": False})
        for change in (
            {"aud": "https://untrusted.example/mcp"},
            {"iss": "https://untrusted.example"},
            {"exp": 1},
        ):
            forged = jwt.encode(
                {**claims, **change}, broker_settings.broker_signing_key, algorithm="HS256"
            )
            assert (
                http.post("/mcp", headers={"Authorization": "Bearer " + forged}).status_code == 401
            )
        assert (
            http.post(
                "/mcp", headers={"Authorization": "Bearer " + upstream["access_token"]}
            ).status_code
            == 401
        )
        refreshed = http.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": issued.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["refresh_token"] != issued.json()["refresh_token"]


def test_registration_limits_and_redirect_policy(broker_settings: Settings) -> None:
    broker = Broker(broker_settings, MemoryStore())
    with (
        patch("catalog.broker.Broker", return_value=broker),
        TestClient(create_app(), base_url="https://catalog.example") as http,
    ):
        client_id = register(http, broker_settings.delegated_scope)
        response = http.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "https://untrusted.example/callback",
                "response_type": "code",
                "code_challenge": "synthetic-challenge",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert http.post("/register", content=b"x" * (16 * 1024 + 1)).status_code == 413
        for _ in range(58):
            assert http.post("/register", json={}).status_code == 400
        limited = http.post("/register", json={})
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "60"


@pytest.mark.parametrize(
    "error", [ServiceRequestError("sensitive"), StoreSetupError(message="sensitive")]
)
def test_storage_outage_is_explicit(broker_settings: Settings, error: Exception) -> None:
    broker = Broker(broker_settings, MemoryStore())
    with (
        patch("catalog.broker.Broker", return_value=broker),
        patch.object(broker.storage, "get", side_effect=error),
        TestClient(create_app(), base_url="https://catalog.example") as http,
    ):
        result = http.post("/mcp", headers={"Authorization": "Bearer invalid"})
        assert result.status_code == 503
        assert "sensitive" not in result.text


def test_broker_deployment_secret_boundary(
    broker_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "AZURE_RESOURCE_GROUP",
        "AZURE_CONTAINER_REGISTRY_NAME",
        "AZURE_CONTAINER_APP_NAME",
        "AZURE_CONTAINER_ENVIRONMENT_NAME",
        "AZURE_PULL_IDENTITY_NAME",
        "AZURE_LOCATION",
    ):
        monkeypatch.setenv(name, "synthetic")
    monkeypatch.delenv("MCP_RESOURCE_URL")
    monkeypatch.delenv("MCP_BROKER_TABLE_ENDPOINT")
    monkeypatch.setattr("sys.argv", ["deploy.py"])
    paths = []

    def run(command: list[str], *, check: bool) -> None:
        assert check
        for secret in (
            broker_settings.broker_client_secret,
            broker_settings.broker_signing_key,
            broker_settings.broker_encryption_key,
        ):
            assert secret not in " ".join(command)
        if command[1:4] == ["deployment", "group", "create"]:
            path = Path(command[command.index("--parameters") + 1][1:])
            paths.append(path)
            assert path.stat().st_mode & 0o777 == 0o600
            parameters = json.loads(path.read_text())["parameters"]
            assert parameters["authMode"]["value"] == "broker"
            assert parameters["apiKey"]["value"] == ""
            assert parameters["brokerClientSecret"]["value"] == broker_settings.broker_client_secret
            assert parameters["brokerSigningKey"]["value"] == broker_settings.broker_signing_key
            assert (
                parameters["brokerEncryptionKey"]["value"] == broker_settings.broker_encryption_key
            )

    with patch.object(deploy.subprocess, "run", side_effect=run):
        deploy.main()
    assert len(paths) == 1 and not paths[0].exists()


@pytest.mark.parametrize(
    "name,value",
    [
        ("MCP_BROKER_CLIENT_ID", ""),
        ("MCP_BROKER_CLIENT_SECRET", ""),
        ("MCP_BROKER_SIGNING_KEY", ""),
        ("MCP_BROKER_ENCRYPTION_KEY", ""),
        ("MCP_BROKER_TABLE_ENDPOINT", "http://untrusted.example"),
        ("MCP_BROKER_REDIRECT_URIS", "https://*.example/callback"),
    ],
)
def test_broker_configuration_fails_closed(
    broker_settings: Settings, monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        Settings.from_env()
