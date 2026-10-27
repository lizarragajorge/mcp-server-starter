# MCP character catalog

An educational Python MCP server with four bundled character records and two
read-only tools. The official MCP SDK serves Streamable HTTP at `/mcp`; `/health`
is anonymous and returns `{"status":"ok"}`. There is no model or external catalog.

The hosted app uses **Entra-backed OAuth with Dynamic discovery**. FastMCP's
maintained OAuthProxy supplies registration, browser consent and S256 PKCE;
the official SDK still serves the tools. Broker tokens reference encrypted
upstream Entra tokens, whose signature, tenant, API audience, lifetime and
delegated `Catalog.Read` scope are also verified. API keys and raw Entra tokens
cannot bypass broker authentication.

## Project layout

- `catalog/`: tools, configuration, authentication and safe JSON logging.
- `infra/`, `azure.yaml`, `scripts/deploy.py`: Azure deployment.
- `tests/`, `.github/workflows/checks.yml`: regression tests and CI.
- [Editable workshop diagram](docs/diagrams/workshop.drawio): agenda and architecture.

## Develop and test

Use Python **3.14** (tested; supported range 3.12-3.14). No Docker or Azure account
is needed for local tests.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt -r requirements-dev.txt
pytest -q
ruff check .
ruff format --check .
```

For an offline development server, use the existing API-key mode:

```sh
export MCP_AUTH_MODE=api_key
export MCP_ALLOWED_HOSTS=localhost,127.0.0.1
export MCP_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m uvicorn catalog.server:create_app --factory \
  --host 127.0.0.1 --port 8000 --no-access-log
```

Clients must send that key in `X-API-Key`; query-string keys are not accepted.
Do not paste credentials into chat or recordings. Visiting `/mcp` in a browser
is not an MCP test; the suite exercises actual SDK clients in modern and legacy
modes, including tool contracts and failure cases.

| Tool | Behavior |
| --- | --- |
| `list_characters(affiliation?)` | Returns `{characters, count}`. Omitted/null means all four; `Rebel Alliance` returns Luke and Leia. Unknown affiliation succeeds with an empty list. |
| `get_character(name)` | Returns `{name, homeworld, affiliation}`; a missing character is an MCP `NOT_FOUND` tool error. |

Matching is exact, case-insensitive and trims whitespace. Blank, non-string and
over-100-character inputs fail; tools must not guess absent facts.

## Deploy or update Azure

**Cloud deployment requires approval and incurs charges.** Prerequisites:
Azure CLI, azd, Bicep, an approved subscription/region and permissions to create
resources, run ACR builds and assign roles. Azure CLI and azd must use the same
subscription. Local Docker is not required: ACR builds the Linux image remotely.

The approved environment already has two single-tenant Entra registrations:
an API exposing delegated `Catalog.Read` with v2 access tokens, and a confidential
upstream client permitted that scope. Their IDs are in private
`.azure/entra-registration.json`. Do not create duplicates or add Graph-wide
permissions. For another approved environment, create equivalent registrations.

Keep deployment settings in the existing ignored, mode-0600 `.env.broker`:

| Setting | Value |
| --- | --- |
| `MCP_AUTH_MODE` | `broker` |
| `MCP_ENTRA_TENANT_ID` | Tenant UUID |
| `MCP_ENTRA_AUDIENCE` | API application/client UUID |
| `MCP_BROKER_CLIENT_ID` | Confidential upstream client UUID |
| `MCP_BROKER_CLIENT_SECRET` | Its credential value |
| `MCP_BROKER_SIGNING_KEY` | Stable generated ASCII secret, at least 43 characters |
| `MCP_BROKER_ENCRYPTION_KEY` | Independent, stable Fernet key |

For a new environment, generate the signing key with `secrets.token_urlsafe(48)`
and the encryption key with `cryptography.fernet.Fernet.generate_key()`, storing
the results securely. **Do not regenerate keys during normal deployment.**

With the virtual environment active and the existing approved azd environment
selected:

```sh
set -a
. ./.env.broker
set +a
azd provision
```

This validates configuration, provisions infrastructure, remotely builds the
image and deploys it with secure temporary parameters. Use `azd provision`, not
`azd deploy`, for updates. Never put secrets in `azd env set`, command arguments,
source control or debug logs.

Broker mode creates a separate app (base app name truncated to 25 characters
plus `-broker`), retaining any original direct-Entra app. Use the effective name
printed by the hook; azd's base app-name output is not the broker app name:

```sh
az containerapp show --resource-group <resource-group> \
  --name <broker-app-name> --query properties.configuration.ingress.fqdn -o tsv
```

Register `https://<broker-fqdn>/auth/callback` as an exact **Web** redirect on the
upstream Entra client, preserving other approved callbacks. Set private
`MCP_URL` and `MCP_RESOURCE_URL` to `https://<broker-fqdn>/mcp`, and
`MCP_ALLOWED_HOSTS` to its hostname. Bicep derives resource/host, Azure Tables
endpoint and managed-identity settings at deployment; private-network broker
storage is not accessible from an ordinary local development server.

## Connect Copilot Studio

1. Use an account/environment with Copilot authoring, connection permissions,
   generative orchestration and tenant data-policy approval.
2. Open **Tools > Add a tool > New tool > Model Context Protocol**.
3. Enter the **broker** `/mcp` URL from `.env.broker`, not the original direct-Entra
   URL. Select **OAuth 2.0 > Dynamic discovery**. No client ID or secret is entered.
4. Create a connection, approve broker consent, then sign in and consent to
   `Catalog.Read` in Entra. Tenant policy may require admin approval.
5. Add to the agent and confirm `list_characters` and `get_character`. Test all
   characters, the two Rebels, and a nonexistent name; inspect actual tool
   arguments, results and error status rather than just the agent's answer.

The default broker callback allowlist covers
`https://global.consent.azure-apim.net/redirect` and its path descendants.
If Copilot supplies a regional callback, add that **exact trusted HTTPS URI**
to `MCP_BROKER_REDIRECT_URIS` and redeploy. Copilot callbacks go in this allowlist,
not on the upstream Entra app. Never allow arbitrary redirects.
UI labels and feature availability vary by tenant; see
[Microsoft's onboarding guide](https://learn.microsoft.com/microsoft-copilot-studio/agent-extend-action-mcp).

## Operations and verification

- Check `/health`, `/.well-known/oauth-protected-resource/mcp` and
  `/.well-known/oauth-authorization-server`; missing/invalid credentials at `/mcp`
  must return **401**. Hosted ingress is HTTPS-only.
- OAuth state is Fernet-encrypted in private-endpoint Azure Tables. Managed
  identity has AcrPull plus Table Data Contributor on the dedicated table;
  public storage and shared-key access are disabled. Storage/key-fetch outages
  return **503**, not anonymous access. Expiry checks are not physical retention
  cleanup; manage retained state explicitly.
- Broker mode is capped at **one replica**: shared storage does not make
  in-process refresh locks distributed. Registration is limited to 16 KiB and
  60 attempts/minute/process; this is a workshop, not production abuse protection.
  Default minimum replicas is zero; use `MCP_MIN_REPLICAS=1` when rehearsing if
  approved, accepting idle charges. ACR, networking, private endpoints/storage,
  compute and Copilot Studio can incur charges.
- Preserve signing/encryption keys. Rotate the upstream credential before its
  90-day expiry and redeploy. Signing-key rotation requires reconnection;
  encryption-key rotation needs a state migration or explicitly approved reset.
- Live discovery, DCR, consent-to-Entra redirects and registration persistence
  after replica replacement were verified. Tests simulate the delegated exchange.
  **Actual Copilot Studio sign-in, refresh and hosted tool calls remain tenant
  checks**, not proven by local tests. No group, per-record authorization or
  downstream on-behalf-of flow is implemented; connection identity behavior
  depends on the Copilot tool/channel configuration.
- Keep ignored `.env`, `.env.entra`, `.env.broker` and `.azure/` private. The first
  two retain local/previous direct-mode settings, not the current broker setup.
- Cleanup requires approval: remove the dedicated Copilot connection, then use
  `azd down` only for the dedicated workshop environment. Entra registrations,
  service principals and consent are outside that resource-group cleanup.

Dependencies are declared in `pyproject.toml` and hash-locked separately for
runtime/development. To intentionally refresh, use `uv pip compile pyproject.toml
--universal --generate-hashes --no-header --no-annotate -o requirements.txt` and
repeat with `--group dev -o requirements-dev.txt`; review and rerun checks.

## License and attribution

Code, tests and documentation use the [Microsoft MIT license](LICENSE). Dependencies
retain their own licenses. The Azure Container Apps icon embedded in the editable
diagram is from Microsoft's Azure Public Service Icons V24, used unchanged under
[Microsoft's architectural/training use terms](https://learn.microsoft.com/azure/architecture/icons/);
it is **not** covered by this project's MIT license. Star Wars names and minimal
facts are an independently written educational fixture, not a copied dataset.
This project is unofficial and has no affiliation with Microsoft, Disney or
Lucasfilm. No character artwork or franchise logos are included.
