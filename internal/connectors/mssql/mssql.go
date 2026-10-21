// Package mssql is the SQL Server connector (connector-v1 M-D) — the Sage 100
// Premium path. Read-only; all the MCP + query logic lives in sqlcommon. This
// package is just the SQL Server DSN + driver wiring.
//
// Config (pushed via config_update, held in memory only):
//
//	{ "host": "10.0.0.5", "port": 1433, "database": "SageDemo",
//	  "user": "conduit_readonly", "password": "...", "encrypt": "disable|true" }
//
// Two authentication modes:
//   - SQL login (default): user + password in the config.
//   - Windows Integrated Auth ("auth":"integrated"): NO user/password — the
//     connector authenticates to SQL Server as its own Windows service
//     identity via SSPI. When the Windows service runs under a gMSA (see
//     install.ps1 -ServiceAccount), that identity IS the gMSA, so no SQL
//     credential is stored anywhere. This connector only wires integrated auth
//     on Windows (the driver's winsspi provider, using the process identity);
//     it is rejected on non-Windows.
//
// Legacy-server TLS opt-ins (both default off, both per connection, both in
// this connection's pushed config only — no env var, no GODEBUG, no global
// setting). They exist so a customer with an old SQL Server never has to fall
// back to "encrypt":"disable" (which sends the SQL login in cleartext):
//
//   - "tlsServerCertSha256": SHA-256 fingerprint (hex; ':' / space separators
//     and any case accepted) of the server's leaf certificate. Chain, hostname
//     and expiry checks are skipped and replaced by an exact, constant-time
//     match of the presented leaf against the pin. It is NOT the driver's
//     trustservercertificate (which trusts any certificate).
//   - "tlsAllowLegacyProtocols": allow TLS 1.0/1.1 and the RSA key-exchange
//     cipher suites (AES-CBC-SHA, AES-GCM) that old servers still negotiate.
//     3DES and RC4 are never enabled.
//
// Both require encryption: they are rejected with "encrypt":"disable".
package mssql

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"runtime"
	"strings"

	mssqldb "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/wyre-technology/conduit-tunnel/internal/connectors/sqlcommon"
)

// Config is the pushed per-site connector config.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
	// Encrypt maps to the driver's encrypt param: "true" (default) or
	// "disable" for lab/demo databases without TLS.
	Encrypt string `json:"encrypt"`
	// Auth selects the authentication mode: "" or "sql" (default) uses
	// user+password; "integrated" uses Windows Integrated Auth (SSPI) as the
	// service's own identity — no SQL credential stored. Integrated requires a
	// Windows host.
	Auth string `json:"auth"`
	// TLSServerCertSha256 pins the server's leaf certificate by SHA-256
	// fingerprint (hex, any case, optional ':' or space separators). When set,
	// CA/hostname/expiry verification is replaced by an exact pin match.
	TLSServerCertSha256 string `json:"tlsServerCertSha256"`
	// TLSAllowLegacyProtocols opts this connection in to TLS 1.0/1.1 and the
	// RSA key-exchange cipher suites for legacy SQL Servers. Default false.
	TLSAllowLegacyProtocols bool `json:"tlsAllowLegacyProtocols"`
}

// Connector is the sqlcommon connector bound to a SQL Server pool.
type Connector = sqlcommon.Connector

// New validates the pushed config and prepares the pool. Connection is lazy —
// a down database does not block config application; the first tool call
// surfaces the connectivity error. `@pN` is SQL Server's placeholder style.
func New(raw json.RawMessage) (*Connector, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("mssql config is not valid JSON: %w", err)
	}
	if err := validateTLSOptIns(cfg); err != nil {
		return nil, err
	}
	dsn, err := buildDSN(cfg)
	if err != nil {
		return nil, err
	}
	db, err := openDB(cfg, dsn)
	if err != nil {
		return nil, err
	}
	return sqlcommon.New(db, "conduit-mssql", func(n int) string { return fmt.Sprintf("@p%d", n) }), nil
}

// openDB opens the pool. With neither TLS switch on it is exactly the plain
// sql.Open("sqlserver", dsn) path, so existing connections are untouched. Only
// when a switch is on is the DSN parsed so the driver's own *tls.Config can be
// mutated (not replaced — that keeps its ServerName and
// DynamicRecordSizingDisabled) and the pool opened from the parsed config.
func openDB(cfg Config, dsn string) (*sql.DB, error) {
	if cfg.TLSServerCertSha256 == "" && !cfg.TLSAllowLegacyProtocols {
		db, err := sql.Open("sqlserver", dsn)
		if err != nil {
			return nil, fmt.Errorf("mssql pool init failed: %w", err)
		}
		return db, nil
	}
	dc, err := msdsn.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("mssql dsn parse failed: %w", err)
	}
	if dc.TLSConfig == nil {
		return nil, fmt.Errorf("mssql TLS opt-ins require an encrypted connection")
	}
	if err := applyLegacyTLS(dc.TLSConfig, cfg); err != nil {
		return nil, err
	}
	if cfg.TLSServerCertSha256 != "" {
		slog.Warn("mssql: tlsServerCertSha256 enabled — CA, hostname and expiry checks are replaced by a certificate pin",
			"host", cfg.Host, "database", cfg.Database)
	}
	if cfg.TLSAllowLegacyProtocols {
		slog.Warn("mssql: tlsAllowLegacyProtocols enabled — TLS 1.0/1.1 and RSA key-exchange cipher suites are allowed",
			"host", cfg.Host, "database", cfg.Database)
	}
	return sql.OpenDB(mssqldb.NewConnectorConfig(dc)), nil
}

// legacyRSACipherSuites are the RSA key-exchange suites old SQL Servers still
// negotiate. 3DES and RC4 are deliberately absent.
var legacyRSACipherSuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// applyLegacyTLS mutates tc in place according to the two opt-ins in cfg. It
// is a no-op when both are off. tc must be the driver's config (so ServerName
// and DynamicRecordSizingDisabled survive).
func applyLegacyTLS(tc *tls.Config, cfg Config) error {
	if cfg.TLSServerCertSha256 != "" {
		pin, err := parseCertPin(cfg.TLSServerCertSha256)
		if err != nil {
			return err
		}
		// Chain/hostname verification is replaced by the pin check below.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("mssql: server presented no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return fmt.Errorf("mssql: server certificate SHA-256 %s does not match tlsServerCertSha256 pin",
					hex.EncodeToString(got[:]))
			}
			return nil
		}
	}
	if cfg.TLSAllowLegacyProtocols {
		tc.MinVersion = tls.VersionTLS10
		var suites []uint16
		for _, cs := range tls.CipherSuites() {
			suites = append(suites, cs.ID)
		}
		for _, id := range legacyRSACipherSuites {
			dup := false
			for _, have := range suites {
				if have == id {
					dup = true
					break
				}
			}
			if !dup {
				suites = append(suites, id)
			}
		}
		tc.CipherSuites = suites
	}
	return nil
}

// parseCertPin normalises a hex fingerprint (case-insensitive, optional ':' or
// space separators) to its 32 raw bytes.
func parseCertPin(s string) ([]byte, error) {
	n := strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s))
	if len(n) != 64 {
		return nil, fmt.Errorf("mssql tlsServerCertSha256 must be a SHA-256 fingerprint: 64 hex characters (':' or space separators allowed); got %d", len(n))
	}
	b, err := hex.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("mssql tlsServerCertSha256 must be a SHA-256 fingerprint: 64 hex characters (':' or space separators allowed); contains non-hex characters")
	}
	return b, nil
}

// validateTLSOptIns rejects the TLS switches when encryption is disabled or
// the pin is malformed, so a bad config fails at New rather than at connect.
func validateTLSOptIns(cfg Config) error {
	if cfg.TLSServerCertSha256 == "" && !cfg.TLSAllowLegacyProtocols {
		return nil
	}
	// "disable" turns TLS off entirely; the driver's "false"/"optional"
	// family encrypts only the login packet, so the opt-ins would not cover
	// data traffic. Both are rejected (matches the console's validation).
	switch strings.ToLower(strings.TrimSpace(cfg.Encrypt)) {
	case "disable", "false", "optional", "no", "0", "f":
		return fmt.Errorf(`mssql "tlsServerCertSha256" / "tlsAllowLegacyProtocols" require full TLS; they cannot be combined with "encrypt":%q`, cfg.Encrypt)
	}
	if cfg.TLSServerCertSha256 != "" {
		if _, err := parseCertPin(cfg.TLSServerCertSha256); err != nil {
			return err
		}
	}
	return nil
}

// buildDSN validates the config and produces the sqlserver:// DSN. Split out
// from New so the DSN shape can be unit-tested directly — in particular the
// load-bearing invariant that integrated mode produces NO userinfo (the empty
// userinfo is exactly what makes the driver's winsspi provider authenticate as
// the process's own identity).
func buildDSN(cfg Config) (string, error) {
	if cfg.Host == "" {
		return "", fmt.Errorf("mssql config requires host")
	}
	if cfg.Database == "" {
		return "", fmt.Errorf("mssql config requires database")
	}
	if cfg.Port == 0 {
		cfg.Port = 1433
	}
	encrypt := cfg.Encrypt
	if encrypt == "" {
		encrypt = "true"
	}

	integrated, err := useIntegratedAuth(cfg)
	if err != nil {
		return "", err
	}

	q := url.Values{"database": {cfg.Database}, "encrypt": {encrypt}}
	dsn := &url.URL{
		Scheme:   "sqlserver",
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: q.Encode(),
	}
	if !integrated {
		// SQL-login mode: credentials go in the DSN userinfo.
		dsn.User = url.UserPassword(cfg.User, cfg.Password)
	}
	// Integrated mode: NO userinfo. On Windows the driver's winsspi provider
	// then authenticates as the process's own identity (the gMSA the service
	// runs as); nothing else to set on the DSN.
	return dsn.String(), nil
}

// useIntegratedAuth resolves and validates the auth mode. It returns true for
// Windows Integrated Auth, false for SQL-login, or an error when the config is
// inconsistent (integrated requested off-Windows, or a SQL-login missing its
// credentials). The mode is matched case- and whitespace-insensitively so a
// plausible value like "Integrated" or " sql " is accepted rather than
// confusingly rejected.
func useIntegratedAuth(cfg Config) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Auth)) {
	case "", "sql":
		if cfg.User == "" || cfg.Password == "" {
			return false, fmt.Errorf(
				`mssql config requires user + password for SQL-login auth; ` +
					`set "auth":"integrated" (Windows service running as a gMSA) to authenticate ` +
					`without a stored SQL credential`)
		}
		return false, nil
	case "integrated":
		if runtime.GOOS != "windows" {
			return false, fmt.Errorf(
				`mssql "auth":"integrated" (Windows Integrated Auth / SSPI) is only wired on a `+
					`Windows host by this connector; it is running on %s. Use SQL-login (user + password) here`,
				runtime.GOOS)
		}
		if cfg.User != "" || cfg.Password != "" {
			return false, fmt.Errorf(
				`mssql "auth":"integrated" takes no user/password — the connector authenticates as ` +
					`its own Windows service identity (the gMSA). Remove user/password, or use ` +
					`"auth":"sql" to authenticate with them`)
		}
		return true, nil
	default:
		return false, fmt.Errorf(`mssql "auth" must be "sql" (default) or "integrated"; got %q`, cfg.Auth)
	}
}
