package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/users/1?tab=access": "/users/1?tab=access",
		"":                    "/",
		"https://evil.test":   "/",
		"//evil.test":         "/",
		"/\\evil.test":        "/",
		"/auth/login":         "/",
		"users":               "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOriginOf(t *testing.T) {
	if got := originOf("https://hub.x.io:8443/base"); got != "https://hub.x.io:8443" {
		t.Fatal(got)
	}
	if got := originOf("http://localhost:8090"); got != "http://localhost:8090" {
		t.Fatal(got)
	}
}

func TestSameOrigin(t *testing.T) {
	s := &Server{origin: "https://hub.x.io"}
	r := httptest.NewRequest("POST", "/api/sync", nil)
	if !s.sameOrigin(r) {
		t.Error("request without browser headers refused")
	}
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if s.sameOrigin(r) {
		t.Error("cross-site request accepted")
	}
	r.Header.Set("Origin", "https://hub.x.io")
	if !s.sameOrigin(r) {
		t.Error("own origin refused")
	}
	r.Header.Set("Origin", "https://hub.x.io.evil.test")
	if s.sameOrigin(r) {
		t.Error("look-alike origin accepted")
	}
}

func TestReadJSON(t *testing.T) {
	var into struct{ Name string }
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"Name":"a","extra":1}`))
	r.Header.Set("Content-Type", "application/json")
	if err := readJSON(r, &into); err == nil {
		t.Error("unknown field accepted")
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"Name":"a"}{}`))
	r.Header.Set("Content-Type", "application/json")
	if err := readJSON(r, &into); err == nil {
		t.Error("two values accepted")
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"Name":"a"}`))
	if err := readJSON(r, &into); err == nil {
		t.Error("missing content type accepted")
	}
}
