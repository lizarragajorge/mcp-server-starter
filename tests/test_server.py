import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from catalog.config import Settings
from catalog.operational import OperationalFormatter


def test_health_and_http_auth(server: tuple[str, str, Path]) -> None:
    url, key, _ = server
    with httpx2.Client(timeout=5, trust_env=False) as http:
        health = http.get(f"{url}/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
        assert http.head(f"{url}/health").status_code == 200
        for method in ("GET", "POST", "DELETE"):
            for headers in ({}, {"X-API-Key": "wrong"}):
                response = http.request(method, f"{url}/mcp", headers=headers)
                assert response.status_code == 401
                assert response.json() == {"error": "unauthorized"}
        assert http.post(f"{url}/mcp", params={"X-API-Key": key}).status_code == 401
        assert (
            http.post(f"{url}/mcp", headers=[("X-API-Key", key), ("X-API-Key", key)]).status_code
            == 401
        )
        headers = {"X-API-Key": key, "Accept": "application/json, text/event-stream"}
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        assert (
            http.post(
                f"{url}/mcp", json=request, headers={**headers, "Host": "untrusted.example"}
            ).status_code
            == 421
        )
        assert (
            http.post(
                f"{url}/mcp",
                json=request,
                headers={**headers, "Origin": "https://untrusted.example"},
            ).status_code
            == 403
        )


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_real_mcp_contracts(server: tuple[str, str, Path], mode: str) -> None:
    url, key, log_path = server

    async def exercise() -> None:
        async with httpx2.AsyncClient(
            headers={"x-api-key": key}, timeout=10, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(f"{url}/mcp", http_client=http), mode=mode
            ) as client:
                tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                assert set(tools) == {"list_characters", "get_character"}
                for tool in tools.values():
                    assert tool.description
                    assert tool.annotations is not None and tool.annotations.read_only_hint
                    assert tool.input_schema["type"] == "object"
                    assert tool.output_schema is not None
                    assert '"$ref"' not in json.dumps(tool.output_schema)
                assert tools["get_character"].input_schema["required"] == ["name"]
                assert set(tools["get_character"].output_schema["required"]) == {
                    "name",
                    "homeworld",
                    "affiliation",
                }
                assert set(tools["list_characters"].output_schema["required"]) == {
                    "characters",
                    "count",
                }

                for args in ({}, {"affiliation": None}):
                    result = await client.call_tool("list_characters", args)
                    assert not result.is_error
                    assert result.structured_content["count"] == 4
                    assert len(result.structured_content["characters"]) == 4
                for affiliation in ("Rebel Alliance", " rebel ALLIANCE "):
                    result = await client.call_tool("list_characters", {"affiliation": affiliation})
                    assert not result.is_error
                    assert result.structured_content["count"] == 2
                    assert {c["name"] for c in result.structured_content["characters"]} == {
                        "Luke Skywalker",
                        "Leia Organa",
                    }
                empty = await client.call_tool("list_characters", {"affiliation": "No such group"})
                assert not empty.is_error
                assert empty.structured_content == {"characters": [], "count": 0}
                for name in ("Luke Skywalker", "  LUKE skywalker  "):
                    result = await client.call_tool("get_character", {"name": name})
                    assert not result.is_error
                    assert result.structured_content == {
                        "name": "Luke Skywalker",
                        "homeworld": "Tatooine",
                        "affiliation": "Rebel Alliance",
                    }
                missing = await client.call_tool("get_character", {"name": "Captain Example"})
                assert missing.is_error and missing.structured_content is None
                assert "NOT_FOUND" in missing.content[0].text
                invalid = ("", "   ", 17, True, [], "a" * 101)
                for value in invalid:
                    for name, argument in (
                        ("get_character", "name"),
                        ("list_characters", "affiliation"),
                    ):
                        result = await client.call_tool(name, {argument: value})
                        assert result.is_error and result.structured_content is None
                for args in ({}, {"name": None}):
                    assert (await client.call_tool("get_character", args)).is_error

    asyncio.run(exercise())
    logs = log_path.read_text()
    assert key not in logs
    assert "Captain Example" not in logs
    events = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    assert any(e.get("tool") == "get_character" and e["outcome"] == "not_found" for e in events)
    assert any(e["event"] == "http_request" and "duration_ms" in e for e in events)


@pytest.mark.parametrize("key", ["", "short", "replace-with-a-generated-secret", "a" * 32 + "\n"])
def test_missing_or_invalid_config(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setenv("MCP_API_KEY", key)
    with pytest.raises(ValueError, match="MCP_API_KEY must"):
        Settings.from_env()
    result = subprocess.run(
        [sys.executable, "-m", "uvicorn", "catalog.server:create_app", "--factory"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "MCP_API_KEY must" in result.stderr


@pytest.mark.parametrize("header", ["Host", "bad\r\nheader", "X-Forwarded-Host", "X-MS-Token"])
def test_reject_reserved_headers(monkeypatch: pytest.MonkeyPatch, header: str) -> None:
    monkeypatch.setenv("MCP_API_KEY", "a" * 32)
    monkeypatch.setenv("MCP_API_KEY_HEADER", header)
    with pytest.raises(ValueError, match="MCP_API_KEY_HEADER"):
        Settings.from_env()


@pytest.mark.parametrize("host", ["", "*", "*.example.com", "https://example.com", "bad/path"])
def test_reject_invalid_hosts(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    monkeypatch.setenv("MCP_API_KEY", "a" * 32)
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", host)
    with pytest.raises(ValueError, match="MCP_ALLOWED_HOSTS"):
        Settings.from_env()


def test_configurable_header(monkeypatch: pytest.MonkeyPatch) -> None:
    from starlette.testclient import TestClient

    from catalog.server import create_app

    monkeypatch.setenv("MCP_API_KEY", "a" * 32)
    monkeypatch.setenv("MCP_API_KEY_HEADER", "X-Catalog-Key")
    with TestClient(create_app(), base_url="http://localhost") as http:
        assert http.post("/mcp", headers={"X-API-Key": "a" * 32}).status_code == 401
        response = http.post(
            "/mcp",
            headers={
                "X-Catalog-Key": "a" * 32,
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "custom-header-test", "version": "1"},
                },
            },
        )
        assert response.status_code == 200
        assert response.json()["result"]["serverInfo"]["name"] == "Workshop Character Catalog"
        assert "mcp-session-id" not in response.headers


def test_library_logs_do_not_include_payloads() -> None:
    record = logging.LogRecord("mcp", logging.ERROR, "", 1, "secret input %s", ("private",), None)
    output = json.loads(OperationalFormatter().format(record))
    assert output["level"] == "ERROR"
    assert output["source"] == "mcp"
    assert "private" not in json.dumps(output)
