package testfakes

// The stand-in's version of the rest of the Asgardeo console: groups
// (listing, reading, deleting), roles, registered applications, sessions and
// the identity governance (login and security policy) API.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type fakeRole struct {
	ID, Name, Audience string
	Permissions        []string
	Users, Groups      map[string]bool
}

type fakeApp struct {
	ID, Name, ClientID, AccessURL string
	Callbacks                     []string
}

type fakeSession struct {
	ID, App string
	Login   time.Time
}

type fakePolicy struct {
	CategoryID, CategoryName, ID, Name string
	Props                              map[string]string
}

func seedRoles() map[string]*fakeRole {
	return map[string]*fakeRole{
		"role-admin":    {ID: "role-admin", Name: "Administrator", Audience: "ORGANIZATION", Permissions: []string{"internal_user_mgt_view"}, Users: map[string]bool{}, Groups: map[string]bool{}},
		"role-everyone": {ID: "role-everyone", Name: "everyone", Audience: "ORGANIZATION", Users: map[string]bool{}, Groups: map[string]bool{}},
	}
}

func seedApps() []fakeApp {
	return []fakeApp{
		{ID: "app-1", Name: "Aventra PM", ClientID: "aventra-client", AccessURL: "https://pm.example.com",
			Callbacks: []string{"regexp=(https://pm.example.com/api/auth/callback|http://localhost:3000/api/auth/callback)"}},
		{ID: "app-2", Name: "My Account", AccessURL: "https://myaccount.example.com"},
	}
}

func seedPolicies() []*fakePolicy {
	return []*fakePolicy{
		{CategoryID: "cat-login", CategoryName: "Login Attempts Security", ID: "conn-lock", Name: "Login Attempts",
			Props: map[string]string{"account.lock.handler.enable": "true", "account.lock.handler.On.Failure.Max.Attempts": "5"}},
		{CategoryID: "cat-pwd", CategoryName: "Password Policies", ID: "conn-history", Name: "Password History",
			Props: map[string]string{"passwordHistory.enable": "false", "passwordHistory.count": "5"}},
	}
}

// consoleScope: the scopes ConsoleAuthorized grants.
func consoleScope(scope string) bool {
	for _, prefix := range []string{"internal_role_mgt_", "internal_application_mgt_", "internal_session_", "internal_governance_"} {
		if strings.HasPrefix(scope, prefix) {
			return true
		}
	}
	return false
}

func (a *Asgardeo) consoleOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.ConsoleAuthorized {
			writeJSON(w, http.StatusForbidden, map[string]string{"detail": "Operation is not permitted"})
			return
		}
		next(w, r)
	}
}

func (a *Asgardeo) consoleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /scim2/Groups", a.scim(a.groupsOnly(a.listGroups)))
	mux.HandleFunc("GET /scim2/Groups/{id}", a.scim(a.groupsOnly(a.getGroup)))
	mux.HandleFunc("DELETE /scim2/Groups/{id}", a.scim(a.groupsOnly(a.deleteGroup)))

	mux.HandleFunc("GET /scim2/v2/Roles", a.scim(a.consoleOnly(a.listRoles)))
	mux.HandleFunc("POST /scim2/v2/Roles", a.scim(a.consoleOnly(a.createRole)))
	mux.HandleFunc("GET /scim2/v2/Roles/{id}", a.scim(a.consoleOnly(a.getRole)))
	mux.HandleFunc("PATCH /scim2/v2/Roles/{id}", a.scim(a.consoleOnly(a.patchRole)))
	mux.HandleFunc("DELETE /scim2/v2/Roles/{id}", a.scim(a.consoleOnly(a.deleteRole)))

	mux.HandleFunc("GET /api/server/v1/applications", a.scim(a.consoleOnly(a.listApps)))
	mux.HandleFunc("GET /api/server/v1/applications/{id}", a.scim(a.consoleOnly(a.getApp)))
	mux.HandleFunc("GET /api/server/v1/applications/{id}/inbound-protocols/oidc", a.scim(a.consoleOnly(a.getAppOIDC)))

	mux.HandleFunc("GET /api/users/v1/{id}/sessions", a.scim(a.consoleOnly(a.listSessions)))
	mux.HandleFunc("DELETE /api/users/v1/{id}/sessions", a.scim(a.consoleOnly(a.endSessions)))
	mux.HandleFunc("DELETE /api/users/v1/{id}/sessions/{sid}", a.scim(a.consoleOnly(a.endSessions)))

	mux.HandleFunc("GET /api/server/v1/identity-governance", a.scim(a.consoleOnly(a.listGovernance)))
	mux.HandleFunc("GET /api/server/v1/identity-governance/{cat}", a.scim(a.consoleOnly(a.getGovernanceCategory)))
	mux.HandleFunc("PATCH /api/server/v1/identity-governance/{cat}/connectors/{conn}", a.scim(a.consoleOnly(a.patchGovernance)))
}

// ------------------------------------------------ helpers for the tests

// AddSession gives a user an active sign-in session and returns its id.
func (a *Asgardeo) AddSession(userID, app string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	id := fmt.Sprintf("session-%d", a.seq)
	a.sessions[userID] = append(a.sessions[userID], fakeSession{ID: id, App: app, Login: time.Now()})
	return id
}

// SessionCount is how many sessions the user has.
func (a *Asgardeo) SessionCount(userID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions[userID])
}

// RoleUsers lists the users a role is assigned to directly.
func (a *Asgardeo) RoleUsers(roleID string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var ids []string
	if r, ok := a.roles[roleID]; ok {
		for id := range r.Users {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// PolicyValue reads one property of a policy.
func (a *Asgardeo) PolicyValue(connectorID, name string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.policies {
		if p.ID == connectorID {
			return p.Props[name]
		}
	}
	return ""
}

// Group returns a group's name, and whether it exists.
func (a *Asgardeo) Group(id string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	g, ok := a.groups[id]
	if !ok {
		return "", false
	}
	return g.Name, true
}

// ---------------------------------------------------------------- groups

func (a *Asgardeo) groupJSON(g *group) map[string]any {
	members := []map[string]string{}
	var ids []string
	for id := range g.Members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		display := id
		if u, ok := a.users[id]; ok {
			display = u.UserName
		}
		members = append(members, map[string]string{"value": id, "display": display})
	}
	return map[string]any{"id": g.ID, "displayName": "DEFAULT/" + g.Name, "members": members,
		"meta": map[string]string{"created": "2026-09-01T00:00:00Z"}}
}

func (a *Asgardeo) listGroups(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var ids []string
	for id := range a.groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	page := []map[string]any{}
	for _, id := range ids {
		page = append(page, a.groupJSON(a.groups[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"totalResults": len(page), "startIndex": 1, "itemsPerPage": len(page), "Resources": page})
}

func (a *Asgardeo) getGroup(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	g, ok := a.groups[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Group not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.groupJSON(g))
}

func (a *Asgardeo) deleteGroup(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.groups[r.PathValue("id")]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Group not found"})
		return
	}
	delete(a.groups, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// ----------------------------------------------------------------- roles

func (a *Asgardeo) roleJSON(role *fakeRole) map[string]any {
	refs := func(set map[string]bool, name func(string) string) []map[string]string {
		var ids []string
		for id := range set {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out := []map[string]string{}
		for _, id := range ids {
			out = append(out, map[string]string{"value": id, "display": name(id)})
		}
		return out
	}
	perms := []map[string]string{}
	for _, p := range role.Permissions {
		perms = append(perms, map[string]string{"value": p, "display": p})
	}
	return map[string]any{
		"id": role.ID, "displayName": role.Name,
		"audience":    map[string]string{"type": role.Audience, "value": "org-1", "display": "zeit26"},
		"permissions": perms,
		"users": refs(role.Users, func(id string) string {
			if u, ok := a.users[id]; ok {
				return u.UserName
			}
			return id
		}),
		"groups": refs(role.Groups, func(id string) string {
			if g, ok := a.groups[id]; ok {
				return g.Name
			}
			return id
		}),
	}
}

func (a *Asgardeo) listRoles(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var ids []string
	for id := range a.roles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	page := []map[string]any{}
	for _, id := range ids {
		page = append(page, a.roleJSON(a.roles[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"totalResults": len(page), "startIndex": 1, "itemsPerPage": len(page), "Resources": page})
}

func (a *Asgardeo) getRole(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	role, ok := a.roles[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Role not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.roleJSON(role))
}

func (a *Asgardeo) createRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.DisplayName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad role"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, role := range a.roles {
		if strings.EqualFold(role.Name, in.DisplayName) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "Role already exists"})
			return
		}
	}
	a.seq++
	role := &fakeRole{ID: fmt.Sprintf("role-%d", a.seq), Name: in.DisplayName, Audience: "ORGANIZATION",
		Users: map[string]bool{}, Groups: map[string]bool{}}
	a.roles[role.ID] = role
	writeJSON(w, http.StatusCreated, a.roleJSON(role))
}

var rolePath = regexp.MustCompile(`^(users|groups)\[value eq "(.*)"\]$`)

func (a *Asgardeo) patchRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value []struct {
				Value string `json:"value"`
			} `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad patch"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	role, ok := a.roles[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Role not found"})
		return
	}
	for _, op := range in.Operations {
		switch op.Op {
		case "add":
			set := role.Users
			if op.Path == "groups" {
				set = role.Groups
			} else if op.Path != "users" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad path"})
				return
			}
			for _, v := range op.Value {
				set[v.Value] = true
			}
		case "remove":
			m := rolePath.FindStringSubmatch(op.Path)
			if m == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad path"})
				return
			}
			if m[1] == "users" {
				delete(role.Users, m[2])
			} else {
				delete(role.Groups, m[2])
			}
		}
	}
	writeJSON(w, http.StatusOK, a.roleJSON(role))
}

func (a *Asgardeo) deleteRole(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.roles[r.PathValue("id")]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Role not found"})
		return
	}
	delete(a.roles, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------- applications

func appJSON(app fakeApp) map[string]any {
	return map[string]any{"id": app.ID, "name": app.Name, "clientId": app.ClientID, "accessUrl": app.AccessURL,
		"templateId": "b9c5e11e-fc78-484b-9bec-015d247561b8", "description": ""}
}

func (a *Asgardeo) listApps(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 30
	}
	page := []map[string]any{}
	for i := offset; i < len(a.apps) && len(page) < limit; i++ {
		page = append(page, appJSON(a.apps[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"totalResults": len(a.apps), "startIndex": offset + 1, "count": len(page), "applications": page})
}

func (a *Asgardeo) findApp(id string) (fakeApp, bool) {
	for _, app := range a.apps {
		if app.ID == id {
			return app, true
		}
	}
	return fakeApp{}, false
}

func (a *Asgardeo) getApp(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	app, ok := a.findApp(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"description": "Application not found"})
		return
	}
	writeJSON(w, http.StatusOK, appJSON(app))
}

func (a *Asgardeo) getAppOIDC(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	app, ok := a.findApp(r.PathValue("id"))
	if !ok || app.ClientID == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"description": "Inbound protocol not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clientId": app.ClientID, "callbackURLs": app.Callbacks,
		"grantTypes": []string{"authorization_code", "refresh_token"}, "allowedOrigins": []string{}, "publicClient": false})
}

// -------------------------------------------------------------- sessions

func (a *Asgardeo) listSessions(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users[r.PathValue("id")]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"description": "User not found"})
		return
	}
	out := []map[string]any{}
	for _, s := range a.sessions[r.PathValue("id")] {
		out = append(out, map[string]any{
			"id": s.ID, "userAgent": "Mozilla/5.0 (X11; Linux x86_64)", "ip": "203.0.113.7",
			"loginTime":      strconv.FormatInt(s.Login.UnixMilli(), 10),
			"lastAccessTime": strconv.FormatInt(s.Login.UnixMilli(), 10),
			"applications":   []map[string]string{{"appName": s.App, "subject": r.PathValue("id")}},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"userId": r.PathValue("id"), "sessions": out})
}

func (a *Asgardeo) endSessions(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	userID, sid := r.PathValue("id"), r.PathValue("sid")
	if sid == "" {
		delete(a.sessions, userID)
	} else {
		kept := a.sessions[userID][:0]
		for _, s := range a.sessions[userID] {
			if s.ID != sid {
				kept = append(kept, s)
			}
		}
		a.sessions[userID] = kept
	}
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------ governance

func (a *Asgardeo) categoryJSON(categoryID string, withProps bool) (map[string]any, bool) {
	var name string
	connectors := []map[string]any{}
	for _, p := range a.policies {
		if p.CategoryID != categoryID {
			continue
		}
		name = p.CategoryName
		c := map[string]any{"id": p.ID, "name": p.ID, "friendlyName": p.Name}
		if withProps {
			var keys []string
			for k := range p.Props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			props := []map[string]string{}
			for _, k := range keys {
				props = append(props, map[string]string{"name": k, "value": p.Props[k], "displayName": k, "description": ""})
			}
			c["properties"] = props
		}
		connectors = append(connectors, c)
	}
	return map[string]any{"id": categoryID, "name": name, "connectors": connectors}, name != ""
}

func (a *Asgardeo) listGovernance(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := map[string]bool{}
	out := []map[string]any{}
	for _, p := range a.policies {
		if seen[p.CategoryID] {
			continue
		}
		seen[p.CategoryID] = true
		c, _ := a.categoryJSON(p.CategoryID, false) // the list leaves values out
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *Asgardeo) getGovernanceCategory(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.categoryJSON(r.PathValue("cat"), true)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"description": "Category not found"})
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *Asgardeo) patchGovernance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Operation  string `json:"operation"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Operation != "UPDATE" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"description": "bad update"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.policies {
		if p.CategoryID == r.PathValue("cat") && p.ID == r.PathValue("conn") {
			for _, prop := range in.Properties {
				p.Props[prop.Name] = prop.Value
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"description": "Connector not found"})
}
