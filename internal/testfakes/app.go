package testfakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// AppUser is an account as a connected application received it.
type AppUser struct {
	ID          string
	UserName    string
	ExternalID  string
	DisplayName string
	Active      bool
	Roles       []string
	Permissions []string
	Department  string
}

// App stands in for a connected application's SCIM 2.0 endpoint, served
// under /scim/v2.
type App struct {
	mu    sync.Mutex
	token string
	users map[string]*AppUser
	seq   int
	// When set, every request is answered with this status (to test retries).
	failWith int
	// Requests seen, as "METHOD path".
	requests []string
	// What /Hub/Catalog answers with.
	Catalog map[string]any
}

func NewApp() *App { return &App{users: map[string]*AppUser{}} }

// SetToken sets the bearer token the application accepts.
func (a *App) SetToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = token
}

// FailWith makes the application refuse everything with status (0: stop).
func (a *App) FailWith(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failWith = status
}

// User returns a copy of the account with this userName, or nil.
func (a *App) User(userName string) *AppUser {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if strings.EqualFold(u.UserName, userName) {
			c := *u
			return &c
		}
	}
	return nil
}

// Count is how many accounts the application holds.
func (a *App) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.users)
}

// Requests returns the requests seen so far.
func (a *App) Requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...)
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /scim/v2/Users", a.list)
	mux.HandleFunc("POST /scim/v2/Users", a.create)
	mux.HandleFunc("PUT /scim/v2/Users/{id}", a.replace)
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}})
	})
	mux.HandleFunc("GET /scim/v2/Hub/Catalog", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		catalog := a.Catalog
		a.mu.Unlock()
		if catalog == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"detail": "no catalog"})
			return
		}
		writeJSON(w, http.StatusOK, catalog)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.requests = append(a.requests, r.Method+" "+r.URL.Path)
		fail, token := a.failWith, a.token
		a.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token || token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "bad token"})
			return
		}
		if fail != 0 {
			writeJSON(w, fail, map[string]string{"detail": "refused on purpose"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type scimUser struct {
	ID          string `json:"id,omitempty"`
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	Roles       []struct {
		Value string `json:"value"`
	} `json:"roles"`
	Entitlements []struct {
		Value string `json:"value"`
	} `json:"entitlements"`
	Hub struct {
		Department  string   `json:"department"`
		Permissions []string `json:"permissions"`
	} `json:"urn:zeit26:params:scim:schemas:extension:hub:2.0:User"`
}

func (a *App) store(id string, in scimUser) *AppUser {
	u := &AppUser{ID: id, UserName: in.UserName, ExternalID: in.ExternalID, DisplayName: in.DisplayName,
		Active: in.Active, Department: in.Hub.Department, Permissions: in.Hub.Permissions}
	for _, r := range in.Roles {
		u.Roles = append(u.Roles, r.Value)
	}
	a.users[id] = u
	return u
}

func (a *App) list(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	a.mu.Lock()
	defer a.mu.Unlock()
	found := []map[string]any{}
	for _, u := range a.users {
		if m := filterPattern.FindStringSubmatch(filter); m != nil && m[1] == "userName" && strings.EqualFold(u.UserName, m[2]) {
			found = append(found, map[string]any{"id": u.ID, "userName": u.UserName})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"totalResults": len(found), "Resources": found})
}

func (a *App) create(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad user"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if strings.EqualFold(u.UserName, in.UserName) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "exists"})
			return
		}
	}
	a.seq++
	u := a.store(fmt.Sprintf("app-user-%d", a.seq), in)
	writeJSON(w, http.StatusCreated, map[string]any{"id": u.ID, "userName": u.UserName})
}

func (a *App) replace(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad user"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users[r.PathValue("id")]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "not found"})
		return
	}
	u := a.store(r.PathValue("id"), in)
	writeJSON(w, http.StatusOK, map[string]any{"id": u.ID, "userName": u.UserName})
}
