package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/zeit26/identity-hub/internal/hub"
	"github.com/zeit26/identity-hub/internal/secrets"
	"github.com/zeit26/identity-hub/internal/store"
)

// OIDCSettings: the Hub's own Asgardeo application (traditional web app).
type OIDCSettings struct {
	Issuer       string // https://api.asgardeo.io/t/<org>/oauth2/token
	ClientID     string
	ClientSecret string
	RedirectURL  string // <public URL>/auth/callback
	// For tests; nil uses a client with a 15 second timeout.
	HTTPClient *http.Client
}

// oidcClient reads Asgardeo's discovery document on first use (so the Hub
// starts even while Asgardeo cannot be reached) and keeps it.
type oidcClient struct {
	settings OIDCSettings
	http     *http.Client

	mu         sync.Mutex
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	endSession string
}

func newOIDCClient(settings OIDCSettings) *oidcClient {
	client := settings.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &oidcClient{settings: settings, http: client}
}

func (c *oidcClient) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.http)
}

func (c *oidcClient) load(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.oauth != nil {
		return nil
	}
	// A dropped connection is worth two more tries before telling the
	// admin Asgardeo cannot be reached.
	var provider *oidc.Provider
	var err error
	for attempt := range 3 {
		if provider, err = oidc.NewProvider(c.ctx(ctx), c.settings.Issuer); err == nil || ctx.Err() != nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&extra)

	c.verifier = provider.Verifier(&oidc.Config{ClientID: c.settings.ClientID})
	c.oauth = &oauth2.Config{
		ClientID:     c.settings.ClientID,
		ClientSecret: c.settings.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.settings.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	c.endSession = extra.EndSession
	return nil
}

// logoutURL signs the browser out of Asgardeo too, then brings it back to
// the Hub's callback (the one URL registered with Asgardeo), which shows the
// signed-out page.
func (c *oidcClient) logoutURL(idToken string) string {
	c.mu.Lock()
	endpoint := c.endSession
	c.mu.Unlock()
	if endpoint == "" {
		return "/signed-out"
	}
	q := url.Values{
		"client_id":                {c.settings.ClientID},
		"post_logout_redirect_uri": {c.settings.RedirectURL},
		"state":                    {"signed-out"},
	}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	return endpoint + "?" + q.Encode()
}

// ------------------------------------------------------------- cookies

func (s *Server) sessionCookieName() string {
	if s.secure {
		return "__Host-hub_session"
	}
	return "hub_session"
}

func (s *Server) loginCookieName() string {
	if s.secure {
		return "__Secure-hub_login"
	}
	return "hub_login"
}

func (s *Server) setCookie(w http.ResponseWriter, name, value, path string, maxAge time.Duration) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   s.secure,
		// Lax: the cookie must come along when Asgardeo sends the browser
		// back; every state-changing request is checked for CSRF anyway.
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge > 0 {
		c.MaxAge = int(maxAge.Seconds())
	} else {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func hashSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// loginState travels, encrypted, in a short-lived cookie between the
// redirect to Asgardeo and the browser's return.
type loginState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Return   string    `json:"r"`
	Expires  time.Time `json:"e"`
}

// ------------------------------------------------------------- sign-in

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.oidc.load(r.Context()); err != nil {
		s.log.Error("reading Asgardeo's OpenID configuration", "error", err)
		s.page(w, http.StatusServiceUnavailable, "Asgardeo is unreachable",
			"The Hub could not reach Asgardeo to sign you in. Try again in a moment.", "/auth/login", "Try again")
		return
	}
	st := loginState{
		State:    secrets.RandomToken(),
		Nonce:    secrets.RandomToken(),
		Verifier: oauth2.GenerateVerifier(),
		Return:   safeReturn(r.URL.Query().Get("return")),
		Expires:  time.Now().Add(10 * time.Minute),
	}
	raw, _ := json.Marshal(st)
	sealed, err := s.box.Seal(string(raw))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.setCookie(w, s.loginCookieName(), sealed, "/auth/", 10*time.Minute)
	target := s.oidc.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if code := q.Get("error"); code != "" {
		s.log.Warn("Asgardeo refused sign-in", "error", code, "description", q.Get("error_description"))
		s.page(w, http.StatusUnauthorized, "Sign-in did not complete",
			"Asgardeo did not sign you in ("+code+").", "/auth/login", "Try again")
		return
	}
	if q.Get("code") == "" {
		// Back from signing out of Asgardeo.
		http.Redirect(w, r, "/signed-out", http.StatusFound)
		return
	}

	st, err := s.readLoginState(r)
	s.setCookie(w, s.loginCookieName(), "", "/auth/", 0)
	if err != nil || subtle.ConstantTimeCompare([]byte(st.State), []byte(q.Get("state"))) != 1 {
		s.page(w, http.StatusBadRequest, "Sign-in expired",
			"This sign-in was started elsewhere or took too long. Start again.", "/auth/login", "Sign in")
		return
	}
	if err := s.oidc.load(r.Context()); err != nil {
		s.page(w, http.StatusServiceUnavailable, "Asgardeo is unreachable",
			"The Hub could not reach Asgardeo to finish signing you in.", "/auth/login", "Try again")
		return
	}

	ctx := s.oidc.ctx(r.Context())
	token, err := s.oidc.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		s.log.Warn("exchanging the sign-in code", "error", err)
		s.page(w, http.StatusBadGateway, "Sign-in did not complete",
			"Asgardeo did not accept the sign-in. Start again.", "/auth/login", "Sign in")
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := s.oidc.verifier.Verify(ctx, rawIDToken)
	if err != nil || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(st.Nonce)) != 1 {
		s.log.Warn("rejecting an ID token", "error", err)
		s.page(w, http.StatusUnauthorized, "Sign-in did not complete",
			"The identity Asgardeo returned could not be verified. Start again.", "/auth/login", "Sign in")
		return
	}

	user, err := s.svc.Identify(r.Context(), idToken.Subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("identifying a sign-in", "subject", idToken.Subject, "error", err)
		s.page(w, http.StatusBadGateway, "Sign-in did not complete",
			"The Hub could not look up your account in Asgardeo. Try again in a moment.", "/auth/login", "Try again")
		return
	}
	role, err := s.svc.AdminRoleOf(r.Context(), user)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if role == hub.RoleNone {
		who := user.Email
		if who == "" {
			who = idToken.Subject
		}
		_ = store.Audit(r.Context(), s.store.Pool, who, "auth.denied", "user", user.ID,
			"Refused dashboard sign-in: not a Hub admin", nil)
		s.page(w, http.StatusForbidden, "No access to the Identity Hub",
			"You signed in as "+who+", which is not a Hub admin. The organization owner can make you one.",
			s.oidc.logoutURL(rawIDToken), "Sign out of Asgardeo")
		return
	}

	sealedIDToken, err := s.box.Seal(rawIDToken)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id := secrets.RandomToken()
	session := store.Session{
		Subject:          user.ID,
		Email:            user.Email,
		Name:             strings.TrimSpace(user.GivenName + " " + user.FamilyName),
		CSRFToken:        secrets.RandomToken(),
		IDTokenEncrypted: sealedIDToken,
		ExpiresAt:        time.Now().Add(s.opts.SessionTTL),
	}
	if err := store.CreateSession(r.Context(), s.store.Pool, hashSessionID(id), session); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = store.Audit(r.Context(), s.store.Pool, user.Email, "auth.signin", "user", user.ID,
		"Signed in to the dashboard as "+string(role), nil)
	s.setCookie(w, s.sessionCookieName(), id, "/", s.opts.SessionTTL)
	http.Redirect(w, r, st.Return, http.StatusFound)
}

func (s *Server) readLoginState(r *http.Request) (loginState, error) {
	var st loginState
	c, err := r.Cookie(s.loginCookieName())
	if err != nil {
		return st, err
	}
	raw, err := s.box.Open(c.Value)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return st, err
	}
	if time.Now().After(st.Expires) {
		return st, errors.New("sign-in expired")
	}
	return st, nil
}

// handleLogout ends the session here and at Asgardeo. It answers JSON
// ({"redirect": ...}) to the dashboard, a redirect to a plain form post.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := s.session(r)
	if p == nil {
		http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
		return
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.PostFormValue("csrf")
	}
	if !s.sameOrigin(r) || subtle.ConstantTimeCompare([]byte(token), []byte(p.Session.CSRFToken)) != 1 {
		writeError(w, http.StatusForbidden, "CSRF", "The request did not come from the dashboard")
		return
	}
	_ = store.DeleteSession(r.Context(), s.store.Pool, p.idHash)
	_ = store.Audit(r.Context(), s.store.Pool, p.Session.Email, "auth.signout", "user", p.Session.Subject, "Signed out", nil)
	s.setCookie(w, s.sessionCookieName(), "", "/", 0)

	idToken, _ := s.box.Open(p.Session.IDTokenEncrypted)
	_ = s.oidc.load(r.Context())
	target := s.oidc.logoutURL(idToken)
	if r.Header.Get("X-CSRF-Token") != "" {
		writeJSON(w, http.StatusOK, map[string]string{"redirect": target})
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleSignedOut(w http.ResponseWriter, r *http.Request) {
	s.page(w, http.StatusOK, "Signed out", "You have signed out of the Identity Hub.", "/auth/login", "Sign in again")
}

// safeReturn keeps a post-sign-in destination on the Hub itself.
func safeReturn(path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
		strings.ContainsAny(path, "\\\r\n") || strings.HasPrefix(path, "/auth/") {
		return "/"
	}
	return path
}

// ------------------------------------------------------------ sessions

type principal struct {
	User    store.User
	Role    hub.AdminRole
	Session store.Session
	idHash  string
}

// session is the live session the request carries, or nil.
func (s *Server) session(r *http.Request) *principal {
	c, err := r.Cookie(s.sessionCookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	idHash := hashSessionID(c.Value)
	session, err := store.GetSession(r.Context(), s.store.Pool, idHash)
	if err != nil {
		return nil
	}
	return &principal{Session: session, idHash: idHash}
}

// authenticate: the signed-in admin, checked again on every request so a
// withdrawn appointment or a suspension takes effect at once.
func (s *Server) authenticate(r *http.Request) (*principal, int) {
	p := s.session(r)
	if p == nil {
		return nil, http.StatusUnauthorized
	}
	user, err := store.GetUser(r.Context(), s.store.Pool, p.Session.Subject)
	if err != nil {
		return nil, http.StatusUnauthorized
	}
	role, err := s.svc.AdminRoleOf(r.Context(), user)
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	if role == hub.RoleNone {
		_ = store.DeleteSession(r.Context(), s.store.Pool, p.idHash)
		return nil, http.StatusForbidden
	}
	p.User, p.Role = user, role
	return p, http.StatusOK
}

type apiHandler func(w http.ResponseWriter, r *http.Request, p *principal) error

func (s *Server) requireAdmin(h apiHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, status := s.authenticate(r)
		switch status {
		case http.StatusOK:
		case http.StatusUnauthorized:
			writeError(w, status, "UNAUTHENTICATED", "Sign in to continue")
			return
		case http.StatusForbidden:
			writeError(w, status, "NOT_ADMIN", "You are no longer a Hub admin")
			return
		default:
			writeError(w, status, "INTERNAL", "Something went wrong. It has been logged.")
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			token := r.Header.Get("X-CSRF-Token")
			if !s.sameOrigin(r) || subtle.ConstantTimeCompare([]byte(token), []byte(p.Session.CSRFToken)) != 1 {
				writeError(w, http.StatusForbidden, "CSRF", "The request did not come from the dashboard")
				return
			}
		}
		if err := h(w, r, p); err != nil {
			s.fail(w, r, err)
		}
	})
}

func requireOwner(h apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		if p.Role != hub.RoleOwner {
			writeError(w, http.StatusForbidden, "OWNER_ONLY", "Only the organization owner can do this")
			return nil
		}
		return h(w, r, p)
	}
}

// sameOrigin: a browser request must come from the Hub's own pages.
// Requests without either header are not from a browser (or a very old
// one); the CSRF token still has to match.
func (s *Server) sameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == s.origin
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	return true
}

// ------------------------------------------------------- server pages

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/png" href="/favicon.png">
<title>{{.Title}} · ZEIT26 Identity Hub</title><link rel="stylesheet" href="/auth/page.css?v=3"></head>
<body><main><div class="brand"><img src="/logo.png" alt="ZEIT26" width="196" height="32"><span>Identity Hub</span></div>
<h1>{{.Title}}</h1><p>{{.Message}}</p>
{{if .Link}}<a class="button" href="{{.Link}}">{{.LinkText}}</a>{{end}}</main></body></html>`))

const pageCSS = `:root{color-scheme:light}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f7f9;color:#101828;font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{background:#fff;border:1px solid #e4e7ec;padding:36px 40px;border-radius:14px;width:min(440px,calc(100vw - 32px));box-shadow:0 12px 16px -4px rgba(16,24,40,.08),0 4px 6px -2px rgba(16,24,40,.03)}
.brand{display:flex;flex-direction:column;align-items:flex-start;gap:8px;padding-bottom:24px;margin-bottom:24px;border-bottom:1px solid #eaecf0}.brand img{height:32px;width:auto}.brand span{color:#667085;font-size:11.5px;font-weight:600;letter-spacing:.12em;text-transform:uppercase}
h1{font-size:20px;font-weight:650;margin:0 0 8px;letter-spacing:-.01em}p{color:#475467;margin:0 0 24px}
.button{display:block;text-align:center;background:#111113;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:600}.button:hover{background:#000}`

func (s *Server) page(w http.ResponseWriter, status int, title, message, link, linkText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, map[string]any{
		"Title": title, "Message": message, "Link": template.URL(link), "LinkText": linkText,
	})
}

func servePageCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	// Revalidated each time, so a restyle shows at once.
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(pageCSS))
}
