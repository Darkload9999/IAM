package config

import (
	"strings"
	"testing"
)

func setValid(t *testing.T) {
	t.Setenv("HUB_PUBLIC_URL", "https://hub.zeit26.test/")
	t.Setenv("DATABASE_URL", "postgres://localhost/hub")
	t.Setenv("ASGARDEO_BASE_URL", "https://api.asgardeo.io/t/zeit26")
	t.Setenv("HUB_OIDC_CLIENT_ID", "id")
	t.Setenv("HUB_OIDC_CLIENT_SECRET", "secret")
	t.Setenv("ASGARDEO_M2M_CLIENT_ID", "m2m")
	t.Setenv("ASGARDEO_M2M_CLIENT_SECRET", "m2m-secret")
	t.Setenv("HUB_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
}

func TestLoad(t *testing.T) {
	setValid(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://hub.zeit26.test" || cfg.RedirectURL() != "https://hub.zeit26.test/auth/callback" {
		t.Errorf("public URL %q, redirect %q", cfg.PublicURL, cfg.RedirectURL())
	}
	if cfg.Issuer() != "https://api.asgardeo.io/t/zeit26/oauth2/token" || !cfg.SecureCookies() {
		t.Errorf("issuer %q, secure %v", cfg.Issuer(), cfg.SecureCookies())
	}
	if cfg.Organization() != "zeit26" {
		t.Errorf("organization %q", cfg.Organization())
	}
	if strings.Contains(cfg.String(), "secret") {
		t.Errorf("String() shows a secret: %s", cfg)
	}
}

func TestEveryProblemAtOnce(t *testing.T) {
	setValid(t)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("HUB_ENCRYPTION_KEY", "c2hvcnQ=")
	t.Setenv("HUB_SYNC_INTERVAL", "often")
	_, err := Load()
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"DATABASE_URL", "HUB_ENCRYPTION_KEY", "HUB_SYNC_INTERVAL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestAsgardeoNeedsHTTPS(t *testing.T) {
	setValid(t)
	t.Setenv("ASGARDEO_BASE_URL", "http://api.asgardeo.io/t/zeit26")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http accepted: %v", err)
	}
}
