// Package web is the Hub's HTTP side: Asgardeo sign-in, the REST API the
// dashboard uses, and the dashboard itself.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zeit26/identity-hub/internal/hub"
	"github.com/zeit26/identity-hub/internal/secrets"
	"github.com/zeit26/identity-hub/internal/store"
)

type Options struct {
	// The Hub's public address, e.g. https://hub.zeit26.com (no trailing /).
	PublicURL  string
	SessionTTL time.Duration
	OIDC       OIDCSettings
	// The built dashboard (index.html and its assets); nil serves a notice.
	UI fs.FS
	// The Asgardeo organization's name, shown in the dashboard.
	Organization string
}

type Server struct {
	opts    Options
	svc     *hub.Service
	store   *store.Store
	box     *secrets.Box
	log     *slog.Logger
	oidc    *oidcClient
	secure  bool
	origin  string
	handler http.Handler
}

func New(opts Options, svc *hub.Service, st *store.Store, box *secrets.Box, log *slog.Logger) *Server {
	s := &Server{
		opts:   opts,
		svc:    svc,
		store:  st,
		box:    box,
		log:    log,
		oidc:   newOIDCClient(opts.OIDC),
		secure: strings.HasPrefix(opts.PublicURL, "https://"),
		origin: originOf(opts.PublicURL),
	}
	s.handler = s.logRequests(s.securityHeaders(s.routes()))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.store.Pool.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})

	// Sign-in (auth.go).
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /signed-out", s.handleSignedOut)
	mux.HandleFunc("GET /auth/page.css", servePageCSS)

	// The API (api.go): every route needs a signed-in admin; those that
	// change something also need the session's CSRF token.
	api := func(pattern string, h apiHandler) {
		mux.Handle(pattern, s.requireAdmin(h))
	}
	owner := func(pattern string, h apiHandler) {
		mux.Handle(pattern, s.requireAdmin(requireOwner(h)))
	}

	api("GET /api/me", s.apiMe)
	api("GET /api/overview", s.apiOverview)
	api("POST /api/sync", s.apiSync)

	api("GET /api/users", s.apiListUsers)
	api("POST /api/users", s.apiCreateUser)
	api("GET /api/users/{id}", s.apiGetUser)
	api("PATCH /api/users/{id}", s.apiUpdateUser)
	api("DELETE /api/users/{id}", s.apiDeleteUser)
	api("POST /api/users/{id}/lock", s.apiLockUser(true))
	api("POST /api/users/{id}/unlock", s.apiLockUser(false))
	api("PUT /api/users/{id}/access/{appId}", s.apiSetAccess)
	api("DELETE /api/users/{id}/access/{appId}", s.apiRevokeAccess)

	api("GET /api/catalog", s.apiCatalog)
	api("GET /api/apps", s.apiListApps)
	api("POST /api/apps", s.apiCreateApp)
	api("GET /api/apps/{id}", s.apiGetApp)
	api("PATCH /api/apps/{id}", s.apiUpdateApp)
	api("DELETE /api/apps/{id}", s.apiDeleteApp)
	api("POST /api/apps/{id}/scim-token", s.apiRotateToken)
	api("POST /api/apps/{id}/group", s.apiCreateGroup)
	api("POST /api/apps/{id}/test", s.apiTestConnection)
	api("POST /api/apps/{id}/import", s.apiImportCatalog)
	api("POST /api/apps/{id}/permissions", s.apiSavePermission)
	api("PATCH /api/apps/{id}/permissions/{pid}", s.apiSavePermission)
	api("DELETE /api/apps/{id}/permissions/{pid}", s.apiDeletePermission)
	api("POST /api/apps/{id}/roles", s.apiSaveRole)
	api("PATCH /api/apps/{id}/roles/{rid}", s.apiSaveRole)
	api("DELETE /api/apps/{id}/roles/{rid}", s.apiDeleteRole)

	api("GET /api/jobs", s.apiListJobs)
	api("POST /api/jobs/{id}/retry", s.apiRetryJob)

	api("GET /api/admins", s.apiListAdmins)
	owner("POST /api/admins", s.apiAddAdmin)
	owner("DELETE /api/admins/{userId}", s.apiRemoveAdmin)

	api("GET /api/audit", s.apiAudit)

	// The Asgardeo console through the Hub (api_console.go).
	api("GET /api/asgardeo/capabilities", s.apiCapabilities)
	api("GET /api/asgardeo/groups", s.apiListGroups)
	api("POST /api/asgardeo/groups", s.apiCreateConsoleGroup)
	api("GET /api/asgardeo/groups/{id}", s.apiGetGroupDetail)
	api("PATCH /api/asgardeo/groups/{id}", s.apiRenameGroup)
	api("DELETE /api/asgardeo/groups/{id}", s.apiDeleteConsoleGroup)
	api("PUT /api/asgardeo/groups/{id}/members/{userId}", s.apiGroupMember(true))
	api("DELETE /api/asgardeo/groups/{id}/members/{userId}", s.apiGroupMember(false))
	api("GET /api/asgardeo/roles", s.apiListConsoleRoles)
	owner("POST /api/asgardeo/roles", s.apiCreateConsoleRole)
	api("GET /api/asgardeo/roles/{id}", s.apiGetConsoleRole)
	owner("DELETE /api/asgardeo/roles/{id}", s.apiDeleteConsoleRole)
	owner("PUT /api/asgardeo/roles/{id}/{kind}/{memberId}", s.apiRoleMember(true))
	owner("DELETE /api/asgardeo/roles/{id}/{kind}/{memberId}", s.apiRoleMember(false))
	api("GET /api/asgardeo/applications", s.apiListConsoleApps)
	api("GET /api/asgardeo/applications/{id}", s.apiGetConsoleApp)
	api("GET /api/asgardeo/policies", s.apiListPolicies)
	owner("PATCH /api/asgardeo/policies/{category}/{id}", s.apiUpdatePolicy)
	api("GET /api/users/{id}/sessions", s.apiListSessions)
	api("DELETE /api/users/{id}/sessions", s.apiEndSessions)
	api("DELETE /api/users/{id}/sessions/{sid}", s.apiEndSessions)
	api("POST /api/users/{id}/reset-password", s.apiResetPassword)

	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "No such API route")
	}))

	// The dashboard (spa.go).
	mux.Handle("/", s.dashboard())
	return mux
}

// securityHeaders applies to every answer.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; "+
			"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------- JSON I/O

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: message}})
}

// fail answers with what went wrong: the service's refusals as they are,
// anything else as a 500 whose cause stays in the log.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var he *hub.Error
	switch {
	case errors.As(err, &he):
		writeError(w, he.Status, he.Code, he.Message)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Not found")
	case errors.As(err, new(badRequest)):
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
	case store.IsCheckViolation(err):
		writeError(w, http.StatusBadRequest, "VALIDATION", "A value is not in the expected format")
	case r.Context().Err() != nil:
		// The admin went away; nothing to answer.
	default:
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "Something went wrong. It has been logged.")
	}
}

// badRequest: the request itself is malformed.
type badRequest string

func (e badRequest) Error() string { return string(e) }

// readJSON decodes a request body of at most 1 MB, refusing unknown fields.
func readJSON(r *http.Request, into any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return badRequest("Send the body as application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return badRequest("The request body is not valid: " + err.Error())
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return badRequest("The request body must be a single JSON value")
	}
	return nil
}

func originOf(rawURL string) string {
	// scheme://host[:port] - PublicURL has no path by configuration, but
	// be safe about a trailing one.
	if i := strings.Index(rawURL, "://"); i >= 0 {
		if j := strings.IndexByte(rawURL[i+3:], '/'); j >= 0 {
			return rawURL[:i+3+j]
		}
	}
	return rawURL
}
