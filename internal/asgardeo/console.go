package asgardeo

// The rest of what the Asgardeo console does, for the Hub to offer in one
// place: groups, roles, the organization's registered applications, users'
// sign-in sessions, the organization's login and security policies, and an
// administrator's password reset. Each needs its own API authorized for the
// Hub's M2M application; Capabilities says which are.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const roleSchema = "urn:ietf:params:scim:schemas:extension:2.0:Role"

// Module is one area of the Asgardeo console, with the scopes it needs.
type Module struct {
	Key    string   `json:"key"`
	Name   string   `json:"name"`
	API    string   `json:"api"`    // as the Asgardeo console names it
	Group  string   `json:"group"`  // Management APIs, ...
	Scopes []string `json:"scopes"` // every one must be granted
}

var Modules = []Module{
	{Key: "users", Name: "Users", API: "SCIM2 Users API", Group: "Management APIs", Scopes: userScopes},
	{Key: "groups", Name: "Groups", API: "SCIM2 Groups API", Group: "Management APIs", Scopes: groupScopes},
	{Key: "roles", Name: "Roles", API: "SCIM2 Roles API", Group: "Management APIs", Scopes: []string{
		"internal_role_mgt_view", "internal_role_mgt_create", "internal_role_mgt_update", "internal_role_mgt_delete"}},
	{Key: "applications", Name: "Applications", API: "Application Management API", Group: "Management APIs", Scopes: []string{
		"internal_application_mgt_view"}},
	{Key: "sessions", Name: "Sessions", API: "Session Management API", Group: "Management APIs", Scopes: []string{
		"internal_session_view", "internal_session_delete"}},
	{Key: "security", Name: "Login & security policies", API: "Identity Governance API", Group: "Management APIs", Scopes: []string{
		"internal_governance_view", "internal_governance_update"}},
}

func allScopes() []string {
	var all []string
	for _, m := range Modules {
		all = append(all, m.Scopes...)
	}
	return all
}

// Capability: a module, and whether the M2M application may use it now.
type Capability struct {
	Module
	Enabled bool     `json:"enabled"`
	Missing []string `json:"missing"`
}

// Capabilities reports, module by module, what Asgardeo lets the Hub do.
// A fresh token is taken first, so a permission just granted in the
// Asgardeo console shows up at once.
func (c *Client) Capabilities(ctx context.Context, fresh bool) ([]Capability, error) {
	if fresh {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
	}
	if _, err := c.accessToken(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Capability, 0, len(Modules))
	for _, m := range Modules {
		cap := Capability{Module: m, Missing: []string{}}
		for _, scope := range m.Scopes {
			if !c.granted[scope] {
				cap.Missing = append(cap.Missing, scope)
			}
		}
		cap.Enabled = len(cap.Missing) == 0
		out = append(out, cap)
	}
	return out, nil
}

// Can reports whether one module is usable.
func (c *Client) Can(ctx context.Context, module string) bool {
	caps, err := c.Capabilities(ctx, false)
	if err != nil {
		return false
	}
	for _, cap := range caps {
		if cap.Key == module {
			return cap.Enabled
		}
	}
	return false
}

// Ref is a member of a group or role: an id and what Asgardeo displays.
type Ref struct {
	ID      string `json:"id"`
	Display string `json:"display"`
}

// ---------------------------------------------------------------- groups

type Group struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Members []Ref     `json:"members"`
	Created time.Time `json:"created"`
}

type scimRef struct {
	Value   string `json:"value"`
	Display string `json:"display"`
}

func refs(in []scimRef) []Ref {
	out := make([]Ref, 0, len(in))
	for _, r := range in {
		out = append(out, Ref{ID: r.Value, Display: strings.TrimPrefix(r.Display, UserStore+"/")})
	}
	return out
}

func parseGroup(raw json.RawMessage) (Group, error) {
	var in struct {
		ID          string    `json:"id"`
		DisplayName string    `json:"displayName"`
		Members     []scimRef `json:"members"`
		Meta        struct {
			Created string `json:"created"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return Group{}, fmt.Errorf("asgardeo: unreadable group: %w", err)
	}
	g := Group{ID: in.ID, Name: strings.TrimPrefix(in.DisplayName, UserStore+"/"), Members: refs(in.Members)}
	g.Created, _ = time.Parse(time.RFC3339Nano, in.Meta.Created)
	return g, nil
}

// ListGroups returns every group, with its members.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var all []Group
	err := c.pages(ctx, "/scim2/Groups", func(raw json.RawMessage) error {
		g, err := parseGroup(raw)
		all = append(all, g)
		return err
	})
	sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	return all, err
}

// GetGroup reads one group; (nil, nil) when there is none.
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	var raw json.RawMessage
	err := c.do(ctx, http.MethodGet, "/scim2/Groups/"+url.PathEscape(id), nil, &raw)
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g, err := parseGroup(raw)
	return &g, err
}

// RenameGroup changes a group's name.
func (c *Client) RenameGroup(ctx context.Context, id, name string) error {
	return c.patch(ctx, "/scim2/Groups/"+url.PathEscape(id), []map[string]any{{
		"op": "replace", "value": map[string]any{"displayName": name},
	}})
}

// DeleteGroup removes a group; one already gone is fine.
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/scim2/Groups/"+url.PathEscape(id), nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// ----------------------------------------------------------------- roles

type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Audience    string `json:"audience"` // organization or application
	AudienceOf  string `json:"audienceOf"`
	Permissions []Ref  `json:"permissions"`
	Users       []Ref  `json:"users"`
	Groups      []Ref  `json:"groups"`
}

func parseRole(raw json.RawMessage) (Role, error) {
	var in struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Audience    struct {
			Type    string `json:"type"`
			Value   string `json:"value"`
			Display string `json:"display"`
		} `json:"audience"`
		Permissions []scimRef `json:"permissions"`
		Users       []scimRef `json:"users"`
		Groups      []scimRef `json:"groups"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return Role{}, fmt.Errorf("asgardeo: unreadable role: %w", err)
	}
	r := Role{ID: in.ID, Name: in.DisplayName, Audience: strings.ToLower(in.Audience.Type),
		AudienceOf: in.Audience.Display, Users: refs(in.Users), Groups: refs(in.Groups)}
	r.Permissions = make([]Ref, 0, len(in.Permissions))
	for _, p := range in.Permissions {
		r.Permissions = append(r.Permissions, Ref{ID: p.Value, Display: p.Display})
	}
	if r.Audience == "" {
		r.Audience = "organization"
	}
	return r, nil
}

// ListRoles returns every role, organization- and application-audience.
func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	var all []Role
	err := c.pages(ctx, "/scim2/v2/Roles", func(raw json.RawMessage) error {
		r, err := parseRole(raw)
		all = append(all, r)
		return err
	})
	sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	return all, err
}

// GetRole reads one role with its permissions and assignments.
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	var raw json.RawMessage
	err := c.do(ctx, http.MethodGet, "/scim2/v2/Roles/"+url.PathEscape(id), nil, &raw)
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, err := parseRole(raw)
	return &r, err
}

// CreateRole creates an organization-audience role with no permissions yet.
func (c *Client) CreateRole(ctx context.Context, name string) (string, error) {
	var body struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/scim2/v2/Roles", map[string]any{
		"schemas":     []string{roleSchema},
		"displayName": name,
	}, &body)
	return body.ID, err
}

// DeleteRole removes a role; one already gone is fine.
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/scim2/v2/Roles/"+url.PathEscape(id), nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// AssignRole gives a role to a user or a group (kind "users" or "groups").
func (c *Client) AssignRole(ctx context.Context, roleID, kind, memberID string) error {
	if kind != "users" && kind != "groups" {
		return fmt.Errorf("asgardeo: unknown role member kind %q", kind)
	}
	return c.patch(ctx, "/scim2/v2/Roles/"+url.PathEscape(roleID), []map[string]any{{
		"op": "add", "path": kind, "value": []map[string]string{{"value": memberID}},
	}})
}

// UnassignRole takes a role away from a user or group; not having it is fine.
func (c *Client) UnassignRole(ctx context.Context, roleID, kind, memberID string) error {
	if kind != "users" && kind != "groups" {
		return fmt.Errorf("asgardeo: unknown role member kind %q", kind)
	}
	err := c.patch(ctx, "/scim2/v2/Roles/"+url.PathEscape(roleID), []map[string]any{{
		"op": "remove", "path": fmt.Sprintf(`%s[value eq "%s"]`, kind, scimString(memberID)),
	}})
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// ---------------------------------------------------------- applications

// Application is an application registered in the Asgardeo organization -
// what people sign in to.
type Application struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ClientID    string   `json:"clientId"`
	AccessURL   string   `json:"accessUrl"`
	Image       string   `json:"image"`
	Template    string   `json:"template"`
	Protocols   []string `json:"protocols,omitempty"`
	// OIDC settings, on a single application's read.
	RedirectURLs   []string `json:"redirectUrls,omitempty"`
	GrantTypes     []string `json:"grantTypes,omitempty"`
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	PublicClient   bool     `json:"publicClient"`
}

type rawApplication struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	ClientID         string `json:"clientId"`
	AccessURL        string `json:"accessUrl"`
	Image            string `json:"imageUrl"`
	Image2           string `json:"image"`
	TemplateID       string `json:"templateId"`
	InboundProtocols []struct {
		Type string `json:"type"`
	} `json:"inboundProtocols"`
}

func (r rawApplication) toApp() Application {
	a := Application{ID: r.ID, Name: r.Name, Description: r.Description, ClientID: r.ClientID,
		AccessURL: r.AccessURL, Image: r.Image, Template: r.TemplateID}
	if a.Image == "" {
		a.Image = r.Image2
	}
	for _, p := range r.InboundProtocols {
		a.Protocols = append(a.Protocols, p.Type)
	}
	return a
}

// ListApplications returns the organization's registered applications.
func (c *Client) ListApplications(ctx context.Context) ([]Application, error) {
	const page = 50
	var all []Application
	for offset := 0; ; offset += page {
		var body struct {
			TotalResults int              `json:"totalResults"`
			Applications []rawApplication `json:"applications"`
		}
		if err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/api/server/v1/applications?limit=%d&offset=%d", page, offset), nil, &body); err != nil {
			return nil, err
		}
		for _, r := range body.Applications {
			all = append(all, r.toApp())
		}
		if len(body.Applications) < page || offset+page >= body.TotalResults {
			sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
			return all, nil
		}
	}
}

// GetApplication reads one application with its OIDC settings.
func (c *Client) GetApplication(ctx context.Context, id string) (*Application, error) {
	var raw rawApplication
	err := c.do(ctx, http.MethodGet, "/api/server/v1/applications/"+url.PathEscape(id), nil, &raw)
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	app := raw.toApp()

	var oidc struct {
		ClientID       string   `json:"clientId"`
		CallbackURLs   []string `json:"callbackURLs"`
		GrantTypes     []string `json:"grantTypes"`
		AllowedOrigins []string `json:"allowedOrigins"`
		PublicClient   bool     `json:"publicClient"`
	}
	err = c.do(ctx, http.MethodGet, "/api/server/v1/applications/"+url.PathEscape(id)+"/inbound-protocols/oidc", nil, &oidc)
	switch {
	case err == nil:
		if app.ClientID == "" {
			app.ClientID = oidc.ClientID
		}
		app.RedirectURLs = splitCallbacks(oidc.CallbackURLs)
		app.GrantTypes = oidc.GrantTypes
		app.AllowedOrigins = oidc.AllowedOrigins
		app.PublicClient = oidc.PublicClient
	case IsStatus(err, http.StatusNotFound), IsStatus(err, http.StatusBadRequest):
		// Not an OIDC application.
	default:
		return nil, err
	}
	return &app, nil
}

// splitCallbacks: Asgardeo stores several callback URLs as one regexp,
// regexp=(a|b); the dashboard shows them one per line.
func splitCallbacks(in []string) []string {
	var out []string
	for _, cb := range in {
		if rest, ok := strings.CutPrefix(cb, "regexp=("); ok && strings.HasSuffix(rest, ")") {
			for _, part := range strings.Split(strings.TrimSuffix(rest, ")"), "|") {
				if part != "" {
					out = append(out, part)
				}
			}
			continue
		}
		out = append(out, cb)
	}
	return out
}

// -------------------------------------------------------------- sessions

type Session struct {
	ID             string    `json:"id"`
	Applications   []string  `json:"applications"`
	UserAgent      string    `json:"userAgent"`
	IP             string    `json:"ip"`
	LoginTime      time.Time `json:"loginTime"`
	LastAccessTime time.Time `json:"lastAccessTime"`
}

// ListSessions returns the user's active sign-in sessions.
func (c *Client) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	var body struct {
		Sessions []struct {
			ID           string `json:"id"`
			Applications []struct {
				AppName string `json:"appName"`
			} `json:"applications"`
			UserAgent      string `json:"userAgent"`
			IP             string `json:"ip"`
			LoginTime      any    `json:"loginTime"`
			LastAccessTime any    `json:"lastAccessTime"`
		} `json:"sessions"`
	}
	err := c.do(ctx, http.MethodGet, "/api/users/v1/"+url.PathEscape(userID)+"/sessions", nil, &body)
	if IsStatus(err, http.StatusNotFound) {
		return []Session{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(body.Sessions))
	for _, s := range body.Sessions {
		session := Session{ID: s.ID, UserAgent: s.UserAgent, IP: s.IP,
			LoginTime: epoch(s.LoginTime), LastAccessTime: epoch(s.LastAccessTime), Applications: []string{}}
		for _, a := range s.Applications {
			session.Applications = append(session.Applications, a.AppName)
		}
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAccessTime.After(out[j].LastAccessTime) })
	return out, nil
}

// TerminateSession ends one session; all of the user's when sessionID is "".
func (c *Client) TerminateSession(ctx context.Context, userID, sessionID string) error {
	path := "/api/users/v1/" + url.PathEscape(userID) + "/sessions"
	if sessionID != "" {
		path += "/" + url.PathEscape(sessionID)
	}
	err := c.do(ctx, http.MethodDelete, path, nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// epoch reads a time Asgardeo gives as milliseconds, in a string or number.
func epoch(v any) time.Time {
	var ms int64
	switch t := v.(type) {
	case float64:
		ms = int64(t)
	case string:
		ms, _ = strconv.ParseInt(t, 10, 64)
	}
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// -------------------------------------------------------- password reset

// ForcePasswordReset has Asgardeo send the person a link to set a new
// password (Admin Initiated Password Reset must be on in Asgardeo:
// Login & Registration > Account Recovery). Their current password stops
// working.
func (c *Client) ForcePasswordReset(ctx context.Context, id string) error {
	return c.patch(ctx, "/scim2/Users/"+url.PathEscape(id), []map[string]any{{
		"op":    "replace",
		"value": map[string]any{wso2Schema: map[string]any{"forcePasswordReset": true}},
	}})
}

// -------------------------------------------------------------- policies

// Policy is one of the organization's login and security settings, e.g.
// the password rules or account locking - a "connector" in Asgardeo.
type Policy struct {
	CategoryID   string           `json:"categoryId"`
	CategoryName string           `json:"categoryName"`
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Properties   []PolicyProperty `json:"properties"`
}

type PolicyProperty struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type rawCategory struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Connectors []struct {
		ID           string           `json:"id"`
		Name         string           `json:"name"`
		FriendlyName string           `json:"friendlyName"`
		Properties   []PolicyProperty `json:"properties"`
	} `json:"connectors"`
}

// ListPolicies returns every login and security setting, category by
// category, with their current values.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	var categories []rawCategory
	if err := c.do(ctx, http.MethodGet, "/api/server/v1/identity-governance", nil, &categories); err != nil {
		return nil, err
	}
	var out []Policy
	for _, summary := range categories {
		category := summary
		// The list may leave the settings' values out; read the category.
		if needsDetail(summary) {
			if err := c.do(ctx, http.MethodGet, "/api/server/v1/identity-governance/"+url.PathEscape(summary.ID), nil, &category); err != nil {
				return nil, err
			}
			if category.Name == "" {
				category.Name = summary.Name
			}
		}
		for _, conn := range category.Connectors {
			name := conn.FriendlyName
			if name == "" {
				name = conn.Name
			}
			props := conn.Properties
			if props == nil {
				props = []PolicyProperty{}
			}
			out = append(out, Policy{CategoryID: category.ID, CategoryName: category.Name, ID: conn.ID, Name: name, Properties: props})
		}
	}
	return out, nil
}

func needsDetail(c rawCategory) bool {
	for _, conn := range c.Connectors {
		if len(conn.Properties) == 0 {
			return true
		}
	}
	return len(c.Connectors) == 0
}

// UpdatePolicy sets some of a policy's properties.
func (c *Client) UpdatePolicy(ctx context.Context, categoryID, connectorID string, values map[string]string) error {
	props := make([]map[string]string, 0, len(values))
	for name, value := range values {
		props = append(props, map[string]string{"name": name, "value": value})
	}
	sort.Slice(props, func(i, j int) bool { return props[i]["name"] < props[j]["name"] })
	return c.do(ctx, http.MethodPatch,
		"/api/server/v1/identity-governance/"+url.PathEscape(categoryID)+"/connectors/"+url.PathEscape(connectorID),
		map[string]any{"operation": "UPDATE", "properties": props}, nil)
}

// --------------------------------------------------------------- helpers

// pages walks a SCIM list, 100 at a time.
func (c *Client) pages(ctx context.Context, path string, each func(json.RawMessage) error) error {
	const page = 100
	for start := 1; ; start += page {
		var body struct {
			TotalResults int               `json:"totalResults"`
			Resources    []json.RawMessage `json:"Resources"`
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s%sstartIndex=%d&count=%d", path, sep, start, page), nil, &body); err != nil {
			return err
		}
		for _, raw := range body.Resources {
			if err := each(raw); err != nil {
				return err
			}
		}
		if len(body.Resources) == 0 || start+page > body.TotalResults {
			return nil
		}
	}
}
