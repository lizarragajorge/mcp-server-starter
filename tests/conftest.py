import os
import secrets
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx2
import pytest


@pytest.fixture(autouse=True)
def isolated_auth_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "MCP_AUTH_MODE",
        "MCP_API_KEY",
        "MCP_API_KEY_HEADER",
        "MCP_ACCESS_TOKEN",
        "MCP_ALLOWED_HOSTS",
        "MCP_ENTRA_TENANT_ID",
        "MCP_ENTRA_AUDIENCE",
        "MCP_RESOURCE_URL",
        "MCP_BROKER_CLIENT_ID",
        "MCP_BROKER_CLIENT_SECRET",
        "MCP_BROKER_SIGNING_KEY",
        "MCP_BROKER_ENCRYPTION_KEY",
        "MCP_BROKER_TABLE_ENDPOINT",
        "MCP_BROKER_IDENTITY_CLIENT_ID",
        "MCP_BROKER_REDIRECT_URIS",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, str, Path]]:
    key = secrets.token_urlsafe(32)
    log_path = tmp_path / "server.log"
    with socket.socket() as listener, log_path.open("w") as log:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        env = {
            **os.environ,
            "MCP_AUTH_MODE": "api_key",
            "MCP_API_KEY": key,
            "MCP_API_KEY_HEADER": "X-API-Key",
            "MCP_ALLOWED_HOSTS": "127.0.0.1,localhost",
        }
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "catalog.server:create_app",
                "--factory",
                "--fd",
                str(listener.fileno()),
                "--no-access-log",
            ],
            env=env,
            pass_fds=(listener.fileno(),),
            stdout=log,
            stderr=log,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            with httpx2.Client(timeout=1, trust_env=False) as http:
                for _ in range(100):
                    if process.poll() is not None:
                        pytest.fail(f"Server exited: {log_path.read_text()}")
                    try:
                        if http.get(f"{url}/health").status_code == 200:
                            break
                    except httpx2.HTTPError:
                        pass
                    time.sleep(0.1)
                else:
                    pytest.fail("Server did not become ready within 10 seconds.")
            yield url, key, log_path
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
