package mssql

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/microsoft/go-mssqldb/msdsn"
)

func TestNewConfigValidation(t *testing.T) {
	cases := []struct{ name, cfg, wantErr string }{
		{"missing host", `{"database":"d","user":"u","password":"p"}`, "host"},
		{"missing database", `{"host":"h","user":"u","password":"p"}`, "database"},
		{"missing creds", `{"host":"h","database":"d"}`, "user + password"},
		{"not json", `nope`, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(json.RawMessage(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	// Valid config prepares a lazy pool without connecting.
	if _, err := New(json.RawMessage(`{"host":"127.0.0.1","database":"demo","user":"u","password":"p","encrypt":"disable"}`)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestAuthModes(t *testing.T) {
	base := `"host":"127.0.0.1","database":"demo","encrypt":"disable"`

	// Unknown auth mode is rejected everywhere.
	if _, err := New(json.RawMessage(`{` + base + `,"auth":"kerberos"}`)); err == nil ||
		!strings.Contains(err.Error(), `"auth" must be`) {
		t.Fatalf("unknown auth mode: want validation error, got %v", err)
	}

	// Explicit "sql" behaves like the default (needs user+password).
	if _, err := New(json.RawMessage(`{` + base + `,"auth":"sql"}`)); err == nil ||
		!strings.Contains(err.Error(), "user + password") {
		t.Fatalf(`auth:"sql" without creds: want "user + password" error, got %v`, err)
	}

	// Integrated auth with stray credentials is rejected (they'd be ignored;
	// fail loud instead of silently). On Windows the OS check passes and the
	// stray-cred check fires; off-Windows the OS check fires first — either
	// way it errors.
	if _, err := New(json.RawMessage(`{` + base + `,"auth":"integrated","user":"u","password":"p"}`)); err == nil {
		t.Fatal(`auth:"integrated" with user/password: want error, got nil`)
	}

	// Case/whitespace variants of a valid mode are accepted, not rejected as
	// unknown: "SQL" normalizes to sql (so it needs creds, not an "auth must
	// be" error).
	if _, err := New(json.RawMessage(`{` + base + `,"auth":" SQL "}`)); err == nil ||
		!strings.Contains(err.Error(), "user + password") {
		t.Fatalf(`auth:" SQL " should normalize to sql, got %v`, err)
	}

	// Integrated auth with no credentials: valid on Windows (builds a
	// credential-less SSPI pool), rejected as unsupported off-Windows.
	_, err := New(json.RawMessage(`{` + base + `,"auth":"integrated"}`))
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf(`auth:"integrated" on windows: want success, got %v`, err)
		}
	} else {
		if err == nil || !strings.Contains(err.Error(), "only wired on a Windows host") {
			t.Fatalf(`auth:"integrated" off-windows: want Windows-only error, got %v`, err)
		}
	}
}

// TestBuildDSNShape asserts the single load-bearing property of integrated
// auth that can be verified without a live SQL Server: integrated mode must
// produce a DSN with NO userinfo (an empty userinfo is exactly what makes the
// driver authenticate as the process's own identity / gMSA), while SQL-login
// mode must carry credentials. Runs the integrated case only on Windows, where
// the auth mode is permitted.
func TestBuildDSNShape(t *testing.T) {
	// SQL-login mode: userinfo present.
	sqlDSN, err := buildDSN(Config{Host: "h", Port: 1433, Database: "d", User: "u", Password: "p", Encrypt: "disable"})
	if err != nil {
		t.Fatalf("sql-login buildDSN: %v", err)
	}
	if !strings.Contains(sqlDSN, "u:p@") {
		t.Fatalf("sql-login DSN should carry credentials, got %q", sqlDSN)
	}

	if runtime.GOOS == "windows" {
		intDSN, err := buildDSN(Config{Host: "h", Port: 1433, Database: "d", Encrypt: "disable", Auth: "integrated"})
		if err != nil {
			t.Fatalf("integrated buildDSN: %v", err)
		}
		// No '@' => no userinfo => driver uses the process identity (SSPI).
		if strings.Contains(intDSN, "@") {
			t.Fatalf("integrated DSN must have NO userinfo (no '@'), got %q", intDSN)
		}
		if !strings.HasPrefix(intDSN, "sqlserver://h:1433?") {
			t.Fatalf("integrated DSN shape unexpected: %q", intDSN)
		}
	}
}

func TestTLSOptInValidation(t *testing.T) {
	base := `"host":"127.0.0.1","database":"d","user":"u","password":"p"`
	good := strings.Repeat("ab", 32)
	cases := []struct{ name, extra, wantErr string }{
		{"short pin", `"tlsServerCertSha256":"abcd"`, "64 hex"},
		{"non-hex pin", `"tlsServerCertSha256":"` + strings.Repeat("zz", 32) + `"`, "non-hex"},
		{"pin with disable", `"tlsServerCertSha256":"` + good + `","encrypt":"disable"`, "encrypt"},
		{"legacy with disable", `"tlsAllowLegacyProtocols":true,"encrypt":"disable"`, "encrypt"},
		{"legacy with login-only encrypt=false", `"tlsAllowLegacyProtocols":true,"encrypt":"false"`, "encrypt"},
		{"pin with encrypt=optional", `"tlsServerCertSha256":"` + good + `","encrypt":"optional"`, "encrypt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(json.RawMessage(`{` + base + `,` + tc.extra + `}`))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	for _, pin := range []string{
		good, strings.ToUpper(good),
		strings.Join(splitN(good, 2), ":"),
		strings.Join(splitN(good, 4), " "),
	} {
		if _, err := New(json.RawMessage(`{` + base + `,"tlsServerCertSha256":"` + pin + `"}`)); err != nil {
			t.Errorf("pin %q rejected: %v", pin, err)
		}
	}
	// explicit false with disable is the default and stays valid
	if _, err := New(json.RawMessage(`{` + base + `,"tlsAllowLegacyProtocols":false,"encrypt":"disable"}`)); err != nil {
		t.Errorf("defaults with disable rejected: %v", err)
	}
}

func splitN(s string, n int) []string {
	var out []string
	for len(s) > 0 {
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}

// driverTLS returns the *tls.Config the connector would hand to the driver:
// the parsed base DSN with applyLegacyTLS applied (same path as openDB).
func driverTLS(t *testing.T, cfg Config) *tls.Config {
	t.Helper()
	cfg.Host, cfg.Database, cfg.User, cfg.Password = "127.0.0.1", "d", "u", "p"
	dsn, err := buildDSN(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := msdsn.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyLegacyTLS(dc.TLSConfig, cfg); err != nil {
		t.Fatal(err)
	}
	return dc.TLSConfig
}

func TestApplyLegacyTLS(t *testing.T) {
	// defaults: untouched driver config
	def := driverTLS(t, Config{})
	if def.InsecureSkipVerify || def.VerifyPeerCertificate != nil || len(def.CipherSuites) != 0 || def.MinVersion != 0 {
		t.Fatalf("default config altered: %+v", def)
	}
	if !def.DynamicRecordSizingDisabled {
		t.Fatal("driver DynamicRecordSizingDisabled lost")
	}

	leg := driverTLS(t, Config{TLSAllowLegacyProtocols: true})
	if leg.MinVersion != tls.VersionTLS10 || !leg.DynamicRecordSizingDisabled || leg.InsecureSkipVerify {
		t.Fatalf("legacy config wrong: %+v", leg)
	}
	have := map[uint16]bool{}
	for _, id := range leg.CipherSuites {
		have[id] = true
	}
	for _, cs := range tls.CipherSuites() {
		if !have[cs.ID] {
			t.Errorf("default suite %s missing", cs.Name)
		}
	}
	for _, id := range legacyRSACipherSuites {
		if !have[id] {
			t.Errorf("legacy suite %s missing", tls.CipherSuiteName(id))
		}
	}
	for _, id := range []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA} {
		if have[id] {
			t.Errorf("forbidden suite %s enabled", tls.CipherSuiteName(id))
		}
	}

	pin := driverTLS(t, Config{TLSServerCertSha256: strings.Repeat("00", 32)})
	if !pin.InsecureSkipVerify || pin.VerifyPeerCertificate == nil || pin.MinVersion != 0 {
		t.Fatalf("pin config wrong: %+v", pin)
	}
	if err := applyLegacyTLS(&tls.Config{}, Config{TLSServerCertSha256: "xyz"}); err == nil {
		t.Fatal("bad pin accepted by applyLegacyTLS")
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "legacy-sql"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

// handshake runs one client handshake against an in-process server using sc,
// returning the client-side error (nil on success).
func handshake(t *testing.T, sc *tls.Config, client *tls.Config) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.(*tls.Conn).Handshake()
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	err = tls.Client(conn, client).Handshake()
	conn.Close()
	<-done
	return err
}

func TestTLSHandshakes(t *testing.T) {
	cert, fp := selfSigned(t)

	// (a) TLS1.0-only server with an RSA-kex CBC suite.
	legacySrv := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}
	pinOnly := Config{TLSServerCertSha256: fp}
	t.Run("legacy server rejected by default", func(t *testing.T) {
		if err := handshake(t, legacySrv, driverTLS(t, pinOnly)); err == nil {
			t.Fatal("TLS1.0 handshake succeeded without tlsAllowLegacyProtocols")
		}
	})
	t.Run("legacy server accepted with opt-in", func(t *testing.T) {
		if err := handshake(t, legacySrv, driverTLS(t, Config{TLSServerCertSha256: fp, TLSAllowLegacyProtocols: true})); err != nil {
			t.Fatalf("legacy handshake failed: %v", err)
		}
	})

	modern := &tls.Config{Certificates: []tls.Certificate{cert}}
	// (b) pin match / mismatch
	t.Run("matching pin", func(t *testing.T) {
		for _, p := range []string{fp, strings.ToUpper(fp), strings.Join(splitN(fp, 2), ":")} {
			if err := handshake(t, modern, driverTLS(t, Config{TLSServerCertSha256: p})); err != nil {
				t.Fatalf("pin %q: %v", p, err)
			}
		}
	})
	t.Run("mismatched pin", func(t *testing.T) {
		err := handshake(t, modern, driverTLS(t, Config{TLSServerCertSha256: strings.Repeat("11", 32)}))
		if err == nil {
			t.Fatal("mismatched pin accepted")
		}
		if !strings.Contains(err.Error(), fp) {
			t.Fatalf("error should include presented fingerprint %s: %v", fp, err)
		}
	})
	// (c) no pin: self-signed fails verification
	t.Run("self-signed without pin", func(t *testing.T) {
		err := handshake(t, modern, driverTLS(t, Config{}))
		var ua x509.UnknownAuthorityError
		if err == nil || !errors.As(err, &ua) {
			t.Fatalf("want unknown-authority error, got %v", err)
		}
	})
}
