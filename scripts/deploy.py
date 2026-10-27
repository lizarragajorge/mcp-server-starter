"""Explicit azd provision hook: build first, then deploy only our authenticated application."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catalog.config import Settings  # noqa: E402


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required deployment variable is absent: {name}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    # Bicep derives the public URL after the managed environment exists.
    settings = Settings.from_env(for_deployment=True)
    min_replicas = os.environ.get("MCP_MIN_REPLICAS", "0")
    if min_replicas not in ("0", "1"):
        raise ValueError("MCP_MIN_REPLICAS must be 0 or 1.")
    if args.check:
        print("Authentication configuration is valid. No secret values displayed.")
        return
    group = required("AZURE_RESOURCE_GROUP")
    registry = required("AZURE_CONTAINER_REGISTRY_NAME")
    app_name = required("AZURE_CONTAINER_APP_NAME")
    if settings.auth_mode == "broker":
        app_name = f"{app_name[:25]}-broker"
    environment = required("AZURE_CONTAINER_ENVIRONMENT_NAME")
    identity = required("AZURE_PULL_IDENTITY_NAME")
    location = required("AZURE_LOCATION")
    tag = f"catalog:{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"
    subprocess.run(
        [
            "az",
            "acr",
            "build",
            "--registry",
            registry,
            "--image",
            tag,
            "--platform",
            "linux/amd64",
            "--file",
            "Dockerfile",
            ".",
        ],
        check=True,
    )
    values = {
        "location": location,
        "appName": app_name,
        "environmentName": environment,
        "registryName": registry,
        "identityName": identity,
        "imageTag": tag,
        "apiKey": settings.api_key,
        "apiKeyHeader": settings.header,
        "authMode": settings.auth_mode,
        "entraTenantId": settings.tenant_id,
        "entraAudience": settings.audience,
        "brokerClientId": settings.broker_client_id,
        "brokerClientSecret": settings.broker_client_secret,
        "brokerSigningKey": settings.broker_signing_key,
        "brokerEncryptionKey": settings.broker_encryption_key,
        "brokerRedirectUris": ",".join(settings.broker_redirect_uris),
        "minReplicas": int(min_replicas),
    }
    # A 0600 temporary file keeps the secure ARM parameter out of command arguments and source.
    with tempfile.TemporaryDirectory(prefix="mcp-deployment-") as directory:
        parameters = Path(directory) / "parameters.json"
        descriptor = os.open(parameters, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(
                {
                    "$schema": (
                        "https://schema.management.azure.com/schemas/2019-04-01/"
                        "deploymentParameters.json#"
                    ),
                    "contentVersion": "1.0.0.0",
                    "parameters": {key: {"value": value} for key, value in values.items()},
                },
                stream,
            )
        subprocess.run(
            [
                "az",
                "deployment",
                "group",
                "create",
                "--resource-group",
                group,
                "--name",
                "catalog-app",
                "--template-file",
                "infra/app.bicep",
                "--parameters",
                f"@{parameters}",
                "--only-show-errors",
                "--output",
                "none",
            ],
            check=True,
        )
    print(f"Application deployed: {app_name}. Verify health, auth, and MCP before presenting.")


if __name__ == "__main__":
    main()
