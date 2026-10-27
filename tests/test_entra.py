import asyncio
import json
import socket
import threading
import time
from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import patch

import httpx2
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.testclient import TestClient

from catalog.config import Settings
from catalog.entra import EntraTokenVerifier
from catalog.server import create_app

TENANT = "11111111-1111-4111-8111-111111111111"
AUDIENCE = "22222222-2222-4222-8222-222222222222"
CLIENT = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("MCP_AUTH_MODE", "entra")
    monkeypatch.setenv("MCP_ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("MCP_ENTRA_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("MCP_RESOURCE_URL", "http://localhost:8000/mcp")
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "localhost,127.0.0.1")
    monkeypatch.setenv("MCP_API_KEY", "old-demo-key-" + "x" * 32)
    return Settings.from_env()


@pytest.fixture
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key: rsa.RSAPrivateKey, **changes: object) -> str:
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": AUDIENCE,
        "tid": TENANT,
        "sub": "synthetic-test-subject",
        "azp": CLIENT,
        "ver": "2.0",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "scp": "Catalog.Read",
    }
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "synthetic-test-key"})


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong-resource"},
        {"aud": [AUDIENCE, "other-resource"]},
        {"iss": "https://untrusted.example"},
        {"tid": "44444444-4444-4444-8444-444444444444"},
        {"exp": 1},
        {"nbf": 9999999999},
        {"iat": 9999999999},
        {"ver": "1.0"},
        {"scp": ["Catalog.Read"]},
        {"azp": ""},
    ],
)
def test_invalid_token_claims(
    settings: Settings, signing_key: rsa.RSAPrivateKey, changes: dict[str, object]
) -> None:
    verifier = EntraTokenVerifier(settings)
    with patch.object(
        verifier.jwks,
        "get_signing_key_from_jwt",
        return_value=SimpleNamespace(key=signing_key.public_key()),
    ):
        assert asyncio.run(verifier.verify_token(token(signing_key, **changes))) is None


def test_valid_signature_and_claims(settings: Settings, signing_key: rsa.RSAPrivateKey) -> None:
    verifier = EntraTokenVerifier(settings)
    assert verifier.jwks.uri == f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"
    with patch.object(
        verifier.jwks,
        "get_signing_key_from_jwt",
        return_value=SimpleNamespace(key=signing_key.public_key()),
    ):
        result = asyncio.run(verifier.verify_token(token(signing_key)))
        assert result is not None
        assert result.client_id == CLIENT
        assert result.scopes == [f"api://{AUDIENCE}/Catalog.Read"]
        assert result.resource == AUDIENCE
        assert result.subject == "synthetic-test-subject"
        forged = token(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        assert asyncio.run(verifier.verify_token(forged)) is None
        symmetric = jwt.encode({"aud": AUDIENCE}, "not-an-rsa-key-" * 4, algorithm="HS256")
        assert asyncio.run(verifier.verify_token(symmetric)) is None
        for value in ("not-a-jwt", "a" * (16 * 1024 + 1)):
            assert asyncio.run(verifier.verify_token(value)) is None


def test_missing_required_claims(settings: Settings, signing_key: rsa.RSAPrivateKey) -> None:
    verifier = EntraTokenVerifier(settings)
    claims = jwt.decode(token(signing_key), options={"verify_signature": False})
    with patch.object(
        verifier.jwks,
        "get_signing_key_from_jwt",
        return_value=SimpleNamespace(key=signing_key.public_key()),
    ):
        for name in ("exp", "iat", "nbf", "iss", "aud", "tid", "sub", "ver", "azp"):
            incomplete = {k: v for k, v in claims.items() if k != name}
            encoded = jwt.encode(incomplete, signing_key, algorithm="RS256")
            assert asyncio.run(verifier.verify_token(encoded)) is None


def test_oauth_http_boundary(settings: Settings, signing_key: rsa.RSAPrivateKey) -> None:
    with (
        patch(
            "jwt.PyJWKClient.get_signing_key_from_jwt",
            return_value=SimpleNamespace(key=signing_key.public_key()),
        ),
        TestClient(create_app(), base_url="http://localhost") as http,
    ):
        assert http.get("/health").json() == {"status": "ok"}
        metadata = http.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == settings.resource_url
        assert metadata.json()["authorization_servers"] == [settings.issuer]
        assert metadata.json()["scopes_supported"] == [settings.delegated_scope]
        for headers in (
            {},
            {"X-API-Key": "old-demo-key-" + "x" * 32},
            {"Authorization": "Bearer not-a-jwt"},
        ):
            response = http.post("/mcp", headers=headers)
            assert response.status_code == 401
            assert "resource_metadata=" in response.headers["www-authenticate"]
        for scope in ("", "Other.Read"):
            response = http.post(
                "/mcp", headers={"Authorization": f"Bearer {token(signing_key, scp=scope)}"}
            )
            assert response.status_code == 403
            assert response.json()["error"] == "insufficient_scope"
        no_scope = jwt.decode(token(signing_key), options={"verify_signature": False})
        no_scope.pop("scp")
        response = http.post(
            "/mcp",
            headers={
                "Authorization": "Bearer " + jwt.encode(no_scope, signing_key, algorithm="RS256")
            },
        )
        assert response.status_code == 403


def test_signing_key_outage_is_explicit(settings: Settings) -> None:
    with (
        patch(
            "jwt.PyJWKClient.get_signing_key_from_jwt",
            side_effect=jwt.PyJWKClientConnectionError("sensitive diagnostic text"),
        ),
        TestClient(create_app(), base_url="http://localhost") as http,
    ):
        response = http.post("/mcp", headers={"Authorization": "Bearer opaque-token"})
        assert response.status_code == 503
        assert "sensitive" not in response.text
        assert "signing keys" in response.text


@pytest.fixture
def entra_server(
    settings: Settings, signing_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[str, str]]:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        monkeypatch.setenv("MCP_RESOURCE_URL", url + "/mcp")
        with patch(
            "jwt.PyJWKClient.get_signing_key_from_jwt",
            return_value=SimpleNamespace(key=signing_key.public_key()),
        ):
            server = uvicorn.Server(uvicorn.Config(create_app(), log_config=None, access_log=False))
            thread = threading.Thread(
                target=server.run, kwargs={"sockets": [listener]}, daemon=True
            )
            thread.start()
            try:
                for _ in range(100):
                    if server.started:
                        break
                    if not thread.is_alive():
                        pytest.fail("Entra test server exited before startup.")
                    time.sleep(0.05)
                else:
                    pytest.fail("Entra test server did not start.")
                yield url, token(signing_key)
            finally:
                server.should_exit = True
                thread.join(timeout=10)
                assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_real_http_with_validated_bearer(entra_server: tuple[str, str], mode: str) -> None:
    url, bearer = entra_server

    async def exercise() -> None:
        async with httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {bearer}"}, timeout=10, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(url + "/mcp", http_client=http), mode=mode
            ) as client:
                assert {t.name for t in (await client.list_tools()).tools} == {
                    "list_characters",
                    "get_character",
                }
                listed = await client.call_tool(
                    "list_characters", {"affiliation": "REBEL ALLIANCE"}
                )
                assert not listed.is_error and listed.structured_content["count"] == 2
                found = await client.call_tool("get_character", {"name": " luke skywalker "})
                assert not found.is_error and found.structured_content["homeworld"] == "Tatooine"
                assert (
                    await client.call_tool("get_character", {"name": "Captain Example"})
                ).is_error

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MCP_AUTH_MODE", "anonymous"),
        ("MCP_ENTRA_TENANT_ID", ""),
        ("MCP_ENTRA_TENANT_ID", "common"),
        ("MCP_ENTRA_AUDIENCE", ""),
        ("MCP_RESOURCE_URL", ""),
        ("MCP_RESOURCE_URL", "https://untrusted.example/mcp"),
        ("MCP_RESOURCE_URL", "http://localhost:8000/mcp?key=bad"),
    ],
)
def test_fail_closed_config(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        Settings.from_env()


def test_entra_config_drops_api_key(settings: Settings) -> None:
    assert settings.api_key == ""
    assert settings.auth_mode == "entra"
    assert "old-demo-key" not in json.dumps(settings.__dict__)
