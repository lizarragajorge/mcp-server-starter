import json
import os
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

import pytest

from scripts import deploy


def test_deployment_secret_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    key = "deployment-test-key-" + "x" * 40
    values = {
        "MCP_API_KEY": key,
        "AZURE_RESOURCE_GROUP": "rg-workshop",
        "AZURE_CONTAINER_REGISTRY_NAME": "acrcatalog",
        "AZURE_CONTAINER_APP_NAME": "ca-catalog",
        "AZURE_CONTAINER_ENVIRONMENT_NAME": "cae-catalog",
        "AZURE_PULL_IDENTITY_NAME": "id-pull",
        "AZURE_LOCATION": "eastus2",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("sys.argv", ["deploy.py"])
    calls: list[list[str]] = []
    temporary_paths: list[Path] = []

    def run(command: list[str], *, check: bool) -> None:
        assert check
        assert key not in " ".join(command)
        calls.append(command)
        if command[1:4] == ["deployment", "group", "create"]:
            path = Path(command[command.index("--parameters") + 1][1:])
            temporary_paths.append(path)
            assert path.stat().st_mode & 0o777 == 0o600
            parameters = json.loads(path.read_text())["parameters"]
            assert parameters["apiKey"]["value"] == key
            assert parameters["minReplicas"]["value"] in (0, 1)
            assert command[-2:] == ["--output", "none"]

    with patch.object(deploy.subprocess, "run", side_effect=run):
        deploy.main()
    assert len(calls) == 2
    assert calls[0][1:3] == ["acr", "build"]
    assert len(temporary_paths) == 1 and not temporary_paths[0].exists()


def test_deployment_missing_key_stops_before_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    monkeypatch.setattr("sys.argv", ["deploy.py", "--check"])
    with patch.object(deploy.subprocess, "run") as run:
        with pytest.raises(ValueError, match="MCP_API_KEY"):
            deploy.main()
        run.assert_not_called()


def test_entra_deployment_has_no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "MCP_AUTH_MODE": "entra",
        "MCP_ENTRA_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "MCP_ENTRA_AUDIENCE": "22222222-2222-4222-8222-222222222222",
        "MCP_ALLOWED_HOSTS": "catalog.example",
        "MCP_API_KEY": "old-api-key-" + "x" * 32,
        "AZURE_RESOURCE_GROUP": "rg-workshop",
        "AZURE_CONTAINER_REGISTRY_NAME": "acrcatalog",
        "AZURE_CONTAINER_APP_NAME": "ca-catalog",
        "AZURE_CONTAINER_ENVIRONMENT_NAME": "cae-catalog",
        "AZURE_PULL_IDENTITY_NAME": "id-pull",
        "AZURE_LOCATION": "eastus2",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("sys.argv", ["deploy.py"])

    def run(command: list[str], *, check: bool) -> None:
        assert check
        if command[1:4] == ["deployment", "group", "create"]:
            path = Path(command[command.index("--parameters") + 1][1:])
            parameters = json.loads(path.read_text())["parameters"]
            assert parameters["apiKey"]["value"] == ""
            assert parameters["authMode"]["value"] == "entra"
            assert parameters["entraAudience"]["value"] == values["MCP_ENTRA_AUDIENCE"]
            assert values["MCP_API_KEY"] not in path.read_text()
            assert "COPILOT_CLIENT_SECRET" not in path.read_text()

    with patch.object(deploy.subprocess, "run", side_effect=run):
        deploy.main()


def test_diagrams_are_editable_and_portable() -> None:
    root = Path(__file__).resolve().parents[1]
    diagram = ElementTree.parse(root / "docs/diagrams/workshop.drawio")
    pages = diagram.findall("diagram")
    pages_by_name = {page.get("name"): page for page in pages}
    assert len(pages_by_name) == len(pages)
    assert {"Agenda", "Architecture"} <= pages_by_name.keys()
    for page in pages:
        assert page.get("name")
        cells = page.findall(".//mxCell")
        assert len([c for c in cells if c.get("vertex") == "1"]) >= 20
        assert any("text;" in c.get("style", "") for c in cells)
    architecture = pages_by_name["Architecture"]
    assert len(architecture.findall(".//mxCell[@edge='1']")) == 7
    images = [
        c.get("style", "")
        for c in architecture.findall(".//mxCell")
        if "shape=image;" in c.get("style", "")
    ]
    assert len(images) == 1 and "data:image/svg+xml," in images[0]
    # Publication files must not contain local-only values or accidental environment snapshots.
    for directory in ("catalog", "docs", "infra", "scripts", ".github"):
        for path in (root / directory).rglob("*"):
            if path.is_file() and path.suffix in (
                ".py",
                ".md",
                ".svg",
                ".drawio",
                ".bicep",
                ".yml",
            ):
                content = path.read_text()
                assert "/Users/" not in content, path
                assert "packagefeedproxy" not in content, path
    for name in (".env", ".env.entra", ".env.broker"):
        assert not (root / name).exists() or os.stat(root / name).st_mode & 0o777 == 0o600
