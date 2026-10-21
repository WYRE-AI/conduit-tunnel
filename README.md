# conduit-tunnel

The Conduit on-prem tunnel — a single-binary Go agent that dials **out** over
WSS and bridges on-prem systems (Sage 100/MSSQL, Veeam, …) into
[Conduit](https://conduit.wyre.ai). It binds **no inbound port**: as long as
outbound 443 works, the site is connected. No firewall holes, ever.

**Build contract:** `docs/onprem-connector-v1.md` in the
[conduit](https://github.com/wyre-technology/conduit) repo. This repo is the Go
agent named there (milestone M-B onward).

## Install (Linux)

`install.sh` downloads the binary from the latest [GitHub release](https://github.com/wyre-technology/conduit-tunnel/releases/latest),
installs it as a hardened systemd service, and starts it. It reads its two
settings from the environment, so an RMM can set site variables and run it
unattended:

```
curl -fsSL https://raw.githubusercontent.com/wyre-technology/conduit-tunnel/main/install.sh | \
  RELAY_URL=wss://conduit-wss.wyre.ai \
  ENROLLMENT_TOKEN=<mint in Conduit: site → Deploy connector> \
  bash
```

Optional: `CONNECTOR_URL` (a direct/signed binary link, e.g. from the Conduit
wizard) or `CONNECTOR_VERSION` (a GitHub Release tag; default `latest`). The
Windows amd64 binary in each release is **Authenticode-signed** (Azure Artifact
Signing); a Windows service wrapper is the M-E follow-up.

## Install (Windows)

`install.ps1` is the Windows counterpart of `install.sh`: it downloads the
signed `conduit-tunnel-windows-amd64.exe` from the latest [GitHub release](https://github.com/wyre-technology/conduit-tunnel/releases/latest),
installs it to `C:\Program Files\conduit-tunnel\`, registers a
`conduit-tunnel` service (auto-start, restart-on-failure), and starts it.
Run it from an **elevated** PowerShell:

```
powershell -ExecutionPolicy Bypass -File .\install.ps1 `
  -RelayUrl wss://conduit-wss.wyre.ai `
  -EnrollmentToken <mint in Conduit: site → Deploy connector>
```

Or fetch-and-run in one line:

```
powershell -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/wyre-technology/conduit-tunnel/main/install.ps1 -OutFile $env:TEMP\install.ps1; & $env:TEMP\install.ps1 -RelayUrl wss://conduit-wss.wyre.ai -EnrollmentToken <mint in Conduit>"
```

The `.exe` is **Authenticode-signed** (Azure Artifact Signing; subject
`WYRE Technology, LLC`) and the installer verifies the signature before
installing. Service logs land in `C:\ProgramData\conduit-tunnel\logs\`.
`-Uninstall` stops and removes the service.

Pass **`-ServiceAccount 'DOMAIN\gmsa$'`** to run the service under a group managed
service account (gMSA). That identity is what the `mssql` connector uses for
Windows Integrated Auth (`auth: "integrated"`), letting it reach SQL Server with
**no SQL credential stored** in Conduit or on the host. This path is new —
validate it against your gMSA + SQL Server before relying on it.

## Run directly (protocol v2)

```
RELAY_URL=wss://conduit-wss.wyre.ai \
ENROLLMENT_TOKEN=<identity-only token minted in Conduit> \
./conduit-tunnel
```

Enrollment is **identity-only** — the token binds the org, not capabilities.
The tunnel comes online empty; Conduit pushes which connectors to run and
their config over the tunnel (the wizard, or the admin API). There is **no
`CAPABILITIES` env var** — the tunnel boot-fails if it is set (that was the
legacy v1 container). Boot otherwise refuses loudly on missing/invalid config.

## Built-in connectors

Compiled in — no plugins, no sidecars. Enabled per-site via cloud-pushed config.

| Slug | What it does |
|---|---|
| `echo` | Connectivity proof (round-trips its input). |
| `mssql` | Read-only SQL Server (Sage 100 Premium) — `query` / `list_tables` / `describe_table`. |
| `postgres` | Read-only PostgreSQL — same three tools. |
| `mysql` | Read-only MySQL/MariaDB — same three tools. |
| `mcp-proxy` | Fronts any local stdio MCP server (e.g. the Veeam MCP server): spawns `{command, args, env, cwd}`, does the MCP handshake, forwards its tools. |
| `http-bridge` | Forwards HTTP requests from cloud vendor MCP containers to allowlisted LAN hosts (`{hosts: [{baseUrl, caCertPem?, insecureSkipVerify?}]}`) — per-host TLS trust, no redirects, 10MiB response cap. No user-facing tools. |

The SQL connectors share `internal/connectors/sqlcommon` (one read-only MCP +
query implementation; each driver package is just its DSN + placeholder style).

### `mssql` and legacy SQL Servers

Old SQL Servers often present a self-signed certificate and/or only speak
TLS 1.0/1.1 with RSA key exchange. Rather than setting `"encrypt":"disable"`
(which sends the SQL login — **password included — in cleartext**), opt in per
connection in its config:

```json
{ "host": "10.0.0.5", "database": "SageDemo", "user": "...", "password": "...",
  "tlsServerCertSha256": "AB:CD:...(64 hex chars)",
  "tlsAllowLegacyProtocols": true }
```

| Field | Default | Effect |
|---|---|---|
| `tlsServerCertSha256` | unset | Pins the server's leaf certificate (SHA-256 of the DER; hex, any case, optional `:`/space separators). Replaces CA, hostname and expiry checks with an exact match. |
| `tlsAllowLegacyProtocols` | `false` | Allows TLS 1.0/1.1 and RSA key-exchange suites (AES-CBC-SHA, AES-GCM). 3DES and RC4 remain off. |

Both require encryption (rejected with `"encrypt":"disable"`) and apply only to
the connection they are set on. Risks:

- The pin skips CA, hostname and expiry checks but binds to exactly one
  certificate, so **re-issuing the certificate breaks the connection until the
  pin is updated**. A mismatch error shows the presented fingerprint.
- TLS 1.0/1.1 and RSA key exchange have known weaknesses (no forward secrecy,
  BEAST/POODLE-class CBC issues).
- Both are still far safer than `encrypt=disable`.
- Older `conduit-tunnel` binaries silently ignore these fields, so the
  connection keeps failing (fail-closed) — safe, but upgrade first.

### Named instances (multiple connectors of one type)

A connector's config key is its **slug** (the `slug__tool` prefix clients see).
By default the slug also names the built-in. To run **several instances of one
built-in**, add a `type` field — the slug becomes a free-form name and `type`
selects the built-in:

```json
{
  "veeam-vbr": { "type": "mcp-proxy", "command": "node", "args": ["/opt/vbr-mcp/build/index.js"], "env": { "PRODUCT_NAME": "vbr", "...": "..." } },
  "veeam-one": { "type": "mcp-proxy", "command": "node", "args": ["/opt/vone-mcp/build/index.js"], "env": { "PRODUCT_NAME": "vone", "...": "..." } }
}
```

Their tools surface as `veeam-vbr__…` and `veeam-one__…`. Omit `type` and the
slug is the type (`{"postgres": {...}}` → the `postgres` built-in), so every
existing config is unchanged.

## Layout

- `cmd/conduit-tunnel` — entry point, env guards, service lifecycle
- `internal/tunnel` — frame protocol (v1 + v2) + WSS client: dial, register,
  heartbeat (30s), reconnect (1s→30s backoff), request dispatch, config apply.
- `internal/connectors` — the built-in connectors + the config-driven registry.

## Development

```
go build -o conduit-tunnel ./cmd/conduit-tunnel   # ~9 MB static binary
go test ./...
```

First light: 2026-07-02 — this agent registered against the production relay
and carried a full `/v1/mcp` echo round-trip
(`gateway → relay → WSS → tunnel → echo → back`) on the day the tunnels
went live in prod.
