// Package config reads the Hub's settings from the environment.
package config

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	// Where the Hub listens, e.g. ":8090".
	Addr string
	// The Hub's public address, e.g. https://hub.zeit26.com - the OIDC
	// redirect URL is derived from it and must be registered in Asgardeo.
	PublicURL string

	DatabaseURL string

	// https://api.asgardeo.io/t/<org>
	AsgardeoBaseURL string
	// The Hub's own Asgardeo application (OIDC, traditional web app).
	OIDCClientID     string
	OIDCClientSecret string
	// The M2M application the Hub manages users (and groups) with.
	M2MClientID     string
	M2MClientSecret string

	// 32 bytes, base64: encrypts the tokens the Hub keeps for applications.
	EncryptionKey []byte

	// How often every Asgardeo user is read back into the Hub.
	SyncInterval time.Duration
	// How long a dashboard session lasts.
	SessionTTL time.Duration
}

// Load reads and checks the environment. Every problem is reported at once.
func Load() (*Config, error) {
	var problems []string
	need := func(name string) string {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			problems = append(problems, name+" is required")
		}
		return value
	}

	cfg := &Config{
		Addr:             envOr("HUB_ADDR", ":8090"),
		PublicURL:        strings.TrimRight(need("HUB_PUBLIC_URL"), "/"),
		DatabaseURL:      need("DATABASE_URL"),
		AsgardeoBaseURL:  strings.TrimRight(need("ASGARDEO_BASE_URL"), "/"),
		OIDCClientID:     need("HUB_OIDC_CLIENT_ID"),
		OIDCClientSecret: need("HUB_OIDC_CLIENT_SECRET"),
		M2MClientID:      need("ASGARDEO_M2M_CLIENT_ID"),
		M2MClientSecret:  need("ASGARDEO_M2M_CLIENT_SECRET"),
	}

	if raw := need("HUB_ENCRYPTION_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			problems = append(problems, "HUB_ENCRYPTION_KEY must be 32 random bytes, base64 (openssl rand -base64 32)")
		}
		cfg.EncryptionKey = key
	}

	var err error
	if cfg.SyncInterval, err = time.ParseDuration(envOr("HUB_SYNC_INTERVAL", "10m")); err != nil {
		problems = append(problems, "HUB_SYNC_INTERVAL must be a duration such as 10m")
	}
	if cfg.SessionTTL, err = time.ParseDuration(envOr("HUB_SESSION_TTL", "8h")); err != nil {
		problems = append(problems, "HUB_SESSION_TTL must be a duration such as 8h")
	}

	for name, value := range map[string]string{
		"HUB_PUBLIC_URL":    cfg.PublicURL,
		"ASGARDEO_BASE_URL": cfg.AsgardeoBaseURL,
	} {
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			problems = append(problems, name+" must be an absolute http(s) URL")
		}
	}
	if strings.HasPrefix(cfg.AsgardeoBaseURL, "http://") {
		problems = append(problems, "ASGARDEO_BASE_URL must use https")
	}

	if len(problems) > 0 {
		return nil, errors.New("configuration: " + strings.Join(problems, "; "))
	}
	return cfg, nil
}

// LoadDotEnv sets variables from a KEY=value file, leaving any already set
// in the environment alone. A missing file is not an error.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if _, set := os.LookupEnv(key); !set {
			os.Setenv(key, value)
		}
	}
	return scanner.Err()
}

// Issuer is Asgardeo's OIDC issuer for the organization.
func (c *Config) Issuer() string { return c.AsgardeoBaseURL + "/oauth2/token" }

// Organization is the Asgardeo organization's name: the last part of
// ASGARDEO_BASE_URL (https://api.asgardeo.io/t/<organization>).
func (c *Config) Organization() string {
	return c.AsgardeoBaseURL[strings.LastIndex(c.AsgardeoBaseURL, "/")+1:]
}

// RedirectURL is where Asgardeo sends a browser back after sign-in.
func (c *Config) RedirectURL() string { return c.PublicURL + "/auth/callback" }

// SecureCookies: cookies are Secure whenever the Hub is served over TLS.
func (c *Config) SecureCookies() bool { return strings.HasPrefix(c.PublicURL, "https://") }

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// String describes the configuration without any secret in it.
func (c *Config) String() string {
	return fmt.Sprintf("addr=%s public=%s asgardeo=%s sync=%s", c.Addr, c.PublicURL, c.AsgardeoBaseURL, c.SyncInterval)
}
