// Package testfakes stands in for Asgardeo and for a connected application
// in the automated tests, so they never touch the real organization. The
// Hub itself only ever talks to the real Asgardeo.
package testfakes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// AsgardeoUser is an account held by the stand-in Asgardeo.
type AsgardeoUser struct {
	ID          string
	UserName    string // DEFAULT/<email> for organization users
	Email       string
	GivenName   string
	FamilyName  string
	AccountType string // Owner, Administrator, Customer
	State       string // UNLOCKED, LOCKED, PENDING_AP
	Locked      bool
	Created     time.Time
	Invited     bool // created with askPassword: an invite email "went out"
	// ResetRequested: an admin-initiated password reset "went out".
	ResetRequested bool
}

type authCode struct {
	subject, nonce, challenge, redirect string
}

// Asgardeo is a stand-in for one Asgardeo organization: the SCIM2 Users
// and Groups APIs, client-credentials tokens, and an OpenID provider.
type Asgardeo struct {
	// BaseURL, like https://api.asgardeo.io/t/<org>; set by whoever serves
	// Handler before the first request.
	BaseURL string

	M2MClientID, M2MClientSecret   string
	OIDCClientID, OIDCClientSecret string
	// Whether the M2M application may use the Groups API.
	GroupsAuthorized bool
	// Whether it may use the Roles, Application Management, Session
	// Management and Identity Governance APIs.
	ConsoleAuthorized bool
	// The account /oauth2/authorize signs in.
	AutoLogin string
	// When set, a created account is answered for only after this long.
	SlowCreate time.Duration
	// DropCreates: accounts asked for are not kept (with SlowCreate: a
	// request lost on the way).
	DropCreates bool

	mu     sync.Mutex
	key    *rsa.PrivateKey
	users  map[string]*AsgardeoUser
	groups map[string]*group
	codes  map[string]authCode
	tokens map[string]bool
	seq    int

	roles    map[string]*fakeRole
	apps     []fakeApp
	sessions map[string][]fakeSession
	policies []*fakePolicy
}

type group struct {
	ID, Name string
	Members  map[string]bool
}

func NewAsgardeo() *Asgardeo {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Asgardeo{
		M2MClientID: "m2m-client", M2MClientSecret: "m2m-secret",
		OIDCClientID: "hub-client", OIDCClientSecret: "hub-secret",
		key:    key,
		users:  map[string]*AsgardeoUser{},
		groups: map[string]*group{},
		codes:  map[string]authCode{},
		tokens: map[string]bool{},

		roles:    seedRoles(),
		apps:     seedApps(),
		sessions: map[string][]fakeSession{},
		policies: seedPolicies(),
	}
}

// AddUser puts an account in the organization, as the Asgardeo console
// would, and returns its id.
func (a *Asgardeo) AddUser(u AsgardeoUser) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addLocked(u)
}

func (a *Asgardeo) addLocked(u AsgardeoUser) string {
	if u.ID == "" {
		a.seq++
		u.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", a.seq)
	}
	if u.AccountType == "" {
		u.AccountType = "Customer"
	}
	if u.UserName == "" {
		u.UserName = "DEFAULT/" + u.Email
	}
	if u.State == "" {
		u.State = "UNLOCKED"
	}
	if u.Created.IsZero() {
		u.Created = time.Now().UTC()
	}
	a.users[u.ID] = &u
	return u.ID
}

// User returns a copy of an account, or nil.
func (a *Asgardeo) User(id string) *AsgardeoUser {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, ok := a.users[id]; ok {
		c := *u
		return &c
	}
	return nil
}

// UserByEmail returns a copy of the account with this address, or nil.
func (a *Asgardeo) UserByEmail(email string) *AsgardeoUser {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if strings.EqualFold(u.Email, email) {
			c := *u
			return &c
		}
	}
	return nil
}

// Edit changes an account directly, as an admin in the Asgardeo console.
func (a *Asgardeo) Edit(id string, change func(u *AsgardeoUser)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, ok := a.users[id]; ok {
		change(u)
	}
}

// Remove deletes an account directly, as in the Asgardeo console.
func (a *Asgardeo) Remove(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, id)
}

// GroupMembers lists the member ids of a group.
func (a *Asgardeo) GroupMembers(groupID string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var ids []string
	if g, ok := a.groups[groupID]; ok {
		for id := range g.Members {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (a *Asgardeo) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", a.token)
	mux.HandleFunc("GET /oauth2/token/.well-known/openid-configuration", a.discovery)
	mux.HandleFunc("GET /oauth2/jwks", a.jwks)
	mux.HandleFunc("GET /oauth2/authorize", a.authorize)
	mux.HandleFunc("GET /oidc/logout", a.logout)

	mux.HandleFunc("GET /scim2/Users", a.scim(a.listUsers))
	mux.HandleFunc("POST /scim2/Users", a.scim(a.createUser))
	mux.HandleFunc("GET /scim2/Users/{id}", a.scim(a.getUser))
	mux.HandleFunc("PATCH /scim2/Users/{id}", a.scim(a.patchUser))
	mux.HandleFunc("DELETE /scim2/Users/{id}", a.scim(a.deleteUser))
	mux.HandleFunc("POST /scim2/Groups", a.scim(a.groupsOnly(a.createGroup)))
	mux.HandleFunc("PATCH /scim2/Groups/{id}", a.scim(a.groupsOnly(a.patchGroup)))
	a.consoleRoutes(mux)
	return mux
}

// ------------------------------------------------------------------ OIDC

func (a *Asgardeo) issuer() string { return a.BaseURL + "/oauth2/token" }

func (a *Asgardeo) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                a.issuer(),
		"authorization_endpoint":                a.BaseURL + "/oauth2/authorize",
		"token_endpoint":                        a.BaseURL + "/oauth2/token",
		"jwks_uri":                              a.BaseURL + "/oauth2/jwks",
		"end_session_endpoint":                  a.BaseURL + "/oidc/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (a *Asgardeo) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &a.key.PublicKey, KeyID: "fake-key", Algorithm: "RS256", Use: "sig",
	}}})
}

func (a *Asgardeo) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != a.OIDCClientID || q.Get("response_type") != "code" {
		http.Error(w, "unknown client or response type", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE (S256) is required", http.StatusBadRequest)
		return
	}
	subject := a.AutoLogin
	a.mu.Lock()
	u, ok := a.users[subject]
	code := randomString()
	if ok && !u.Locked {
		a.codes[code] = authCode{subject: subject, nonce: q.Get("nonce"),
			challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	}
	a.mu.Unlock()

	back, _ := url.Parse(q.Get("redirect_uri"))
	answer := url.Values{"state": {q.Get("state")}}
	if !ok || u.Locked {
		answer.Set("error", "access_denied")
	} else {
		answer.Set("code", code)
	}
	back.RawQuery = answer.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (a *Asgardeo) logout(w http.ResponseWriter, r *http.Request) {
	back := r.URL.Query().Get("post_logout_redirect_uri")
	if back == "" {
		w.Write([]byte("signed out"))
		return
	}
	target, _ := url.Parse(back)
	target.RawQuery = url.Values{"state": {r.URL.Query().Get("state")}}.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (a *Asgardeo) token(w http.ResponseWriter, r *http.Request) {
	id, secret, _ := r.BasicAuth()
	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)
	if id == "" {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}

	switch r.PostFormValue("grant_type") {
	case "client_credentials":
		if id != a.M2MClientID || secret != a.M2MClientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
		var granted []string
		for _, scope := range strings.Fields(r.PostFormValue("scope")) {
			if strings.HasPrefix(scope, "internal_user_mgt_") ||
				(a.GroupsAuthorized && strings.HasPrefix(scope, "internal_group_mgt_")) ||
				(a.ConsoleAuthorized && consoleScope(scope)) {
				granted = append(granted, scope)
			}
		}
		token := randomString()
		a.mu.Lock()
		a.tokens[token] = true
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": strings.Join(granted, " "),
		})

	case "authorization_code":
		if id != a.OIDCClientID || secret != a.OIDCClientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
		a.mu.Lock()
		code, ok := a.codes[r.PostFormValue("code")]
		delete(a.codes, r.PostFormValue("code"))
		a.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || code.redirect != r.PostFormValue("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != code.challenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		user := a.User(code.subject)
		now := time.Now()
		claims := map[string]any{
			"iss": a.issuer(), "aud": a.OIDCClientID, "sub": code.subject,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": code.nonce,
		}
		if user != nil {
			claims["email"] = user.Email
			claims["given_name"] = user.GivenName
			claims["family_name"] = user.FamilyName
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": randomString(), "token_type": "Bearer", "expires_in": 3600,
			"id_token": a.sign(claims),
		})

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (a *Asgardeo) sign(claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256,
		Key: jose.JSONWebKey{Key: a.key, KeyID: "fake-key"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, _ := signed.CompactSerialize()
	return out
}

// ------------------------------------------------------------------ SCIM

func (a *Asgardeo) scim(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		a.mu.Lock()
		ok := a.tokens[token]
		a.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "invalid token"})
			return
		}
		next(w, r)
	}
}

func (a *Asgardeo) groupsOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.GroupsAuthorized {
			writeJSON(w, http.StatusForbidden, map[string]string{"detail": "Operation is not permitted"})
			return
		}
		next(w, r)
	}
}

func userJSON(u *AsgardeoUser) map[string]any {
	return map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":       u.ID,
		"userName": u.UserName,
		"name":     map[string]string{"givenName": u.GivenName, "familyName": u.FamilyName},
		// Asgardeo lists emails as plain strings.
		"emails": []string{u.Email},
		"meta":   map[string]string{"created": u.Created.Format(time.RFC3339Nano)},
		"urn:scim:wso2:schema": map[string]any{
			"userAccountType": u.AccountType,
			"accountState":    u.State,
			"accountLocked":   strconv.FormatBool(u.Locked),
		},
	}
}

var filterPattern = regexp.MustCompile(`^(userName|emails) eq "(.*)"$`)

func (a *Asgardeo) listUsers(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var all []*AsgardeoUser
	for _, u := range a.users {
		all = append(all, u)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Created.Before(all[j].Created) || (all[i].Created.Equal(all[j].Created) && all[i].ID < all[j].ID)
	})

	if f := r.URL.Query().Get("filter"); f != "" {
		m := filterPattern.FindStringSubmatch(f)
		if m == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "unsupported filter"})
			return
		}
		value := strings.ReplaceAll(m[2], `\"`, `"`)
		var matched []*AsgardeoUser
		for _, u := range all {
			if (m[1] == "userName" && strings.EqualFold(u.UserName, value)) ||
				(m[1] == "emails" && strings.EqualFold(u.Email, value)) {
				matched = append(matched, u)
			}
		}
		all = matched
	}

	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if start < 1 {
		start = 1
	}
	if count <= 0 {
		count = 100
	}
	page := []map[string]any{}
	for i := start - 1; i < len(all) && len(page) < count; i++ {
		page = append(page, userJSON(all[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"totalResults": len(all), "startIndex": start,
		"itemsPerPage": len(page), "Resources": page})
}

func (a *Asgardeo) getUser(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "User not found"})
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

func (a *Asgardeo) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserName string `json:"userName"`
		Name     struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
		} `json:"name"`
		Emails []struct {
			Value string `json:"value"`
		} `json:"emails"`
		WSO2 struct {
			AskPassword bool `json:"askPassword"`
		} `json:"urn:scim:wso2:schema"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Emails) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad user"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if strings.EqualFold(u.UserName, in.UserName) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "User already exists"})
			return
		}
	}
	state := "UNLOCKED"
	if in.WSO2.AskPassword {
		state = "PENDING_AP"
	}
	id := a.addLocked(AsgardeoUser{UserName: in.UserName, Email: in.Emails[0].Value, GivenName: in.Name.GivenName,
		FamilyName: in.Name.FamilyName, State: state, Invited: in.WSO2.AskPassword})
	body := userJSON(a.users[id])
	if a.DropCreates {
		delete(a.users, id)
	}
	if a.SlowCreate > 0 {
		a.mu.Unlock()
		time.Sleep(a.SlowCreate)
		a.mu.Lock()
	}
	writeJSON(w, http.StatusCreated, body)
}

func (a *Asgardeo) patchUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Operations []struct {
			Op    string         `json:"op"`
			Value map[string]any `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad patch"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "User not found"})
		return
	}
	for _, op := range in.Operations {
		if name, ok := op.Value["name"].(map[string]any); ok {
			u.GivenName, _ = name["givenName"].(string)
			u.FamilyName, _ = name["familyName"].(string)
		}
		if ext, ok := op.Value["urn:scim:wso2:schema"].(map[string]any); ok {
			if reset, ok := ext["forcePasswordReset"].(bool); ok && reset {
				u.ResetRequested = true
			}
			if locked, ok := ext["accountLocked"].(bool); ok {
				u.Locked = locked
				if locked {
					u.State = "LOCKED"
				} else if u.State == "LOCKED" {
					u.State = "UNLOCKED"
				}
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(userJSON(u))
}

func (a *Asgardeo) deleteUser(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users[r.PathValue("id")]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "User not found"})
		return
	}
	delete(a.users, r.PathValue("id"))
	for _, g := range a.groups {
		delete(g.Members, r.PathValue("id"))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Asgardeo) createGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	g := &group{ID: fmt.Sprintf("group-%d", a.seq), Name: in.DisplayName, Members: map[string]bool{}}
	a.groups[g.ID] = g
	writeJSON(w, http.StatusCreated, map[string]any{"id": g.ID, "displayName": g.Name})
}

var memberPath = regexp.MustCompile(`^members\[value eq "(.*)"\]$`)

func (a *Asgardeo) patchGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value struct {
				DisplayName string `json:"displayName"`
				Members     []struct {
					Value string `json:"value"`
				} `json:"members"`
			} `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad patch"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	g, ok := a.groups[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Group not found"})
		return
	}
	for _, op := range in.Operations {
		switch op.Op {
		case "replace":
			if op.Value.DisplayName != "" {
				g.Name = op.Value.DisplayName
			}
		case "add":
			for _, m := range op.Value.Members {
				g.Members[m.Value] = true
			}
		case "remove":
			if m := memberPath.FindStringSubmatch(op.Path); m != nil {
				delete(g.Members, m[1])
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{}`))
}

// --------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func randomString() string {
	raw := make([]byte, 18)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}
