# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **`mssql`: per-connection legacy-TLS opt-ins** (WYREAI-542), so customers
  with legacy SQL Servers never need `"encrypt":"disable"`. Both default off,
  live only in that connection's pushed config (no env var, no `GODEBUG`), and
  are rejected together with `"encrypt":"disable"`:
  - `tlsServerCertSha256` — SHA-256 fingerprint of the server's leaf
    certificate (hex, any case, optional `:`/space separators). Skips CA,
    hostname and expiry verification and instead requires an exact match
    (constant-time). Mismatch errors include the presented fingerprint.
    Re-issuing the certificate breaks the connection until the pin is updated.
  - `tlsAllowLegacyProtocols` — allows TLS 1.0/1.1 and the RSA key-exchange
    suites `TLS_RSA_WITH_AES_{128,256}_CBC_SHA` and
    `TLS_RSA_WITH_AES_{128,256}_GCM_SHA{256,384}` on top of Go's defaults. 3DES
    and RC4 stay disabled.
  - A warning is logged when a connector is created with either switch on.
  - Older binaries silently ignore these fields, so the connection keeps
    failing (fail-closed).

## [0.4.0] - 2026-07-24

### Changed

- **Repo/binary rename: `conduit-connector` → `conduit-tunnel`**. The
  product is now called "Tunnel"; this repo, its Go module path
  (`github.com/wyre-technology/conduit-tunnel`), the compiled binary, the
  Windows service name (`conduit-tunnel`), install paths
  (`C:\Program Files\conduit-tunnel\`, `/usr/local/bin/conduit-tunnel`), and
  log directories (`C:\ProgramData\conduit-tunnel\logs\`,
  `/etc/conduit-tunnel`) all move to the new name. Release asset names
  become `conduit-tunnel-{linux-amd64,linux-arm64,windows-amd64.exe}`.
  Installer parameter/env-var names (`-EnrollmentToken`/`-RelayUrl`/
  `-Version`; `RELAY_URL`/`ENROLLMENT_TOKEN`/`CONNECTOR_VERSION`) and the
  `WYRE Technology` Authenticode signer subject are unchanged. Built-in
  data-source connectors (`mssql`, `postgres`, `mysql`, `http-bridge`,
  `mcp-proxy`, `echo`) keep the "connector" sub-concept name — only the
  repo/binary/product identity changes. Tags v0.1.0–v0.3.0 remain
  `conduit-connector` releases and are not renamed.

### Added

- **`http-bridge` built-in connector**: forwards `http/forward` JSON-RPC
  payloads from the tunnel to LAN HTTP hosts on a cloud-pushed allowlist
  (component-wise URL matching — scheme/host/port/path-prefix). Per-host TLS
  trust (`caCertPem` or `insecureSkipVerify`), hop-by-hop header stripping,
  redirects returned not followed, 10 MiB response cap. Powers on-prem
  ConnectWise Manage/Automate and IT Glue support without running vendor
  code on the customer box.

## [0.3.0] - 2026-07-05

gMSA / Windows Integrated Auth for SQL Server — the "zero stored SQL
credentials" path — validated end-to-end on a real Azure AD + gMSA + SQL
Server domain.

### Added

- **gMSA / Windows Integrated Auth for `mssql`**: the SQL Server connector accepts `"auth":"integrated"` — no `user`/`password`; it authenticates to SQL Server as its own Windows service identity via SSPI. Run the Windows service under a gMSA (`install.ps1 -ServiceAccount 'DOMAIN\gmsa$'`) and **no SQL credential is stored anywhere**, in Conduit or on the host. Windows-only; rejected off-Windows. Validated end-to-end against a real AD gMSA + SQL Server: the connector authenticates as `DOMAIN\gmsa$` (confirmed via `SUSER_SNAME()`).

### Fixed

- **`install.ps1 -ServiceAccount` (gMSA)**: setting the service logon account to a gMSA failed with `sc.exe config obj= password= "" -> error 1639` (empty password rejected). Now uses `Win32_Service.Change` (accepts an empty gMSA password cleanly) and auto-grants the account **`SeServiceLogonRight`** via `secedit` (setting the account programmatically doesn't grant it, so the service otherwise couldn't start). Found + fixed via the real gMSA validation above.

## [0.2.0] - 2026-07-05

Windows-service support: the same signed single binary now runs as a native
Windows service, installed via `install.ps1` — bringing the Windows-heavy
Sage/MSSQL fleet to parity with the Linux systemd path.

### Added

- **Windows service support**: the connector runs as a native Windows service (auto-detects the SCM; graceful stop on service Stop/Shutdown; logs to `C:\ProgramData\conduit-connector\logs\`), plus **`install.ps1`** — the Windows counterpart of `install.sh` (downloads the signed `.exe` from the public release, verifies its Authenticode signature, registers the `conduit-connector` service with auto-start + restart-on-failure, sets config in the service registry, starts it). `-Uninstall` removes it.

## [0.1.0] - 2026-07-05

First tagged release of the Go on-prem connector (protocol v2). A single static
binary that dials out over WSS, enrolls identity-only, and runs cloud-pushed
connectors — echo, read-only SQL (mssql/postgres/mysql), and `mcp-proxy` (front
any local MCP server, e.g. Veeam). Ships with a Linux `install.sh` and a signed
release pipeline.

### Added

- **Windows code-signing wired into the release (M-E)**: the Release workflow now Authenticode-signs the Windows `.exe` via Azure Artifact Signing (`Azure/trusted-signing-action`) in a `sign-windows` job. Inert until the `SIGNING_CERT_PROFILE` repo variable + `AZURE_*` secrets are set (post identity-validation); until then releases ship the unsigned `.exe` as before. A signing failure blocks the release rather than shipping unsigned.

- **Named connector instances**: a connector config may carry an optional `type` field that decouples the routing **slug** from the built-in that implements it — so a site can run multiple instances of one built-in (e.g. two `mcp-proxy` servers under `veeam-vbr` + `veeam-one`, each surfaced as its own `slug__tool`). Absent `type`, the slug is the type (every existing config unchanged).

- **mcp-proxy diagnostics**: a failed local MCP server (bad command, backend unreachable at startup, mid-request crash) now surfaces the child's recent **stderr** in the connector error instead of an opaque `closed stdout: EOF` — so an operator sees the actual cause.

- **`mcp-proxy` connector**: a generic connector that spawns a LOCAL MCP
  server (any stdio MCP server — e.g. the Veeam MCP servers) and forwards
  tools/list + tools/call over the tunnel. Config: `{command, args, env, cwd}`.
  Tunnels an existing MCP server unchanged instead of rewriting it as a
  built-in — the whole MCP ecosystem, reachable on-prem.

- **Linux install path (M-E)**: `install.sh` (RMM-variable-aware: reads
  RELAY_URL + ENROLLMENT_TOKEN from env, downloads the binary, installs a
  hardened systemd service, starts it) + a **Release workflow** that publishes
  cross-compiled binaries + SHA256SUMS as GitHub Release assets on a `v*` tag.
  Windows service + signed installer remain the M-E follow-up.

- **`mysql` connector** (read-only, MySQL/MariaDB): same read-only query / list_tables / describe_table tools as postgres/mssql, over the go-sql-driver. list_tables also excludes MySQL system schemas (mysql, performance_schema).

- `list_tables` now excludes engine system catalogs (pg_catalog / information_schema / sys) so it returns the site's own tables, not hundreds of system rows.

- **`postgres` connector** (read-only): PostgreSQL/`pgx`-backed query /
  list_tables / describe_table, same read-only guard + row caps as `mssql`.
  Driver-agnostic query + MCP logic extracted to `internal/connectors/sqlcommon`
  so mssql and postgres share one implementation (only DSN + placeholder style
  differ).


- **`mssql` connector** (M-D, the Sage 100 Premium path): read-only SQL Server
  tools — `query` (single SELECT/WITH statement, comment/multi-statement
  smuggling refused, row caps), `list_tables`, `describe_table`. Config pushed
  via `config_update` (host/port/database/user/password/encrypt); lazy
  connection pool so a down database never blocks config application. The
  real enforcement is the site's read-only SQL principal; the code guard is
  belt-and-suspenders.

### Changed

- **Protocol v2 (breaking, pre-release)**: the agent now registers identity-only
  (`capabilities: []`) and receives connector config from Conduit via
  `config_update`/`config_ack` (pairs with conduit PR #633). `CAPABILITIES` is
  no longer an agent setting — boot fails loud if it is set, pointing at the
  legacy v1 container for the old behavior. Connector enablement is
  config-driven (`connectors.Registry`), in-memory: on restart the cloud
  re-pushes. Outbound wire shapes are pinned by tests (`capabilities: []` /
  `applied: []` must serialize as arrays — Go omitempty would drop them and
  the relay would treat the frame as a protocol violation).

### Added

- `transient_unavailable` register_nack reason: treated as retryable (reconnect-with-backoff) rather than permanent stop — pairs with conduit's relay hardening (conduit PR #632).

- Initial Go agent (M-B skeleton): frame-v1 tunnel client (dial, register,
  heartbeat, reconnect-with-backoff, request dispatch) faithfully ported from
  conduit's TypeScript `tunnel-client.ts`/`frame-protocol.ts`, built-in `echo`
  connector, six-guard env boot discipline, structured JSON logging.
  Verified against the production relay (registration + full `/v1/mcp` echo
  round-trip) on day one.
