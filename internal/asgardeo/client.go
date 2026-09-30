// Package asgardeo talks to Asgardeo's SCIM 2.0 APIs as the Hub's M2M
// application: the organization's users (read, create, update, lock,
// delete) and, when the application is authorized for them, groups.
package asgardeo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The organization's own user store: the accounts people sign in to
// applications with. Console administrators and the organization owner are
// kept elsewhere, and their usernames carry no store prefix.
const UserStore = "DEFAULT"

const (
	userSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	wso2Schema  = "urn:scim:wso2:schema"
	patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

var userScopes = []string{
	"internal_user_mgt_create", "internal_user_mgt_list", "internal_user_mgt_view",
	"internal_user_mgt_update", "internal_user_mgt_delete",
}

var groupScopes = []string{
	"internal_group_mgt_create", "internal_group_mgt_view",
	"internal_group_mgt_update", "internal_group_mgt_delete",
}

// Error is a refusal from Asgardeo; Detail is Asgardeo's own reason.
// Unanswered: the request may or may not have been carried out - Asgardeo
// did not answer (a timeout, or a connection dropped after sending).
type Error struct {
	Status     int
	Detail     string
	Unanswered bool
}

func (e *Error) Error() string { return fmt.Sprintf("asgardeo: %d %s", e.Status, e.Detail) }

// IsStatus reports whether err is an Asgardeo refusal with this status.
func IsStatus(err error, status int) bool {
	var ae *Error
	return errors.As(err, &ae) && ae.Status == status
}

// User is an Asgardeo account as the Hub sees it.
type User struct {
	ID           string
	UserName     string // as Asgardeo returns it, e.g. DEFAULT/ada@example.com
	Email        string
	GivenName    string
	FamilyName   string
	AccountType  string // Owner, Administrator, Customer
	AccountState string // UNLOCKED, LOCKED, PENDING_AP, ...
	Locked       bool
	Created      time.Time
}

// InUserStore: an account that can sign in to the organization's apps.
func (u User) InUserStore() bool { return strings.HasPrefix(u.UserName, UserStore+"/") }

type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
	// How long Asgardeo is given to answer a read, and a change.
	readTimeout, writeTimeout time.Duration

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
	granted     map[string]bool
}

func New(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		// Per-request limits are set in do; this is only a backstop.
		http:         &http.Client{Timeout: 2 * time.Minute},
		readTimeout:  defaultReadTimeout,
		writeTimeout: defaultWriteTimeout,
	}
}

// CanManageGroups: whether the M2M application was granted the SCIM2 Groups
// API. Without it the Hub still works; applications just get no Asgardeo
// access group.
func (c *Client) CanManageGroups(ctx context.Context) bool {
	if _, err := c.accessToken(ctx); err != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, scope := range groupScopes {
		if !c.granted[scope] {
			return false
		}
	}
	return true
}

// ListUsers returns every account in the organization, page by page.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	const page = 100
	var all []User
	for start := 1; ; start += page {
		var body struct {
			TotalResults int               `json:"totalResults"`
			Resources    []json.RawMessage `json:"Resources"`
		}
		if err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/scim2/Users?startIndex=%d&count=%d", start, page), nil, &body); err != nil {
			return nil, err
		}
		for _, raw := range body.Resources {
			user, err := parseUser(raw)
			if err != nil {
				return nil, err
			}
			all = append(all, user)
		}
		if len(body.Resources) == 0 || start+page > body.TotalResults {
			return all, nil
		}
	}
}

// GetUser reads one account; (nil, nil) when there is none.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	var raw json.RawMessage
	err := c.do(ctx, http.MethodGet, "/scim2/Users/"+url.PathEscape(id), nil, &raw)
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user, err := parseUser(raw)
	return &user, err
}

// FindByEmail returns the organization-store account for an address, or nil.
func (c *Client) FindByEmail(ctx context.Context, email string) (*User, error) {
	for _, filter := range []string{
		fmt.Sprintf(`userName eq "%s/%s"`, UserStore, scimString(email)),
		fmt.Sprintf(`emails eq "%s"`, scimString(email)),
	} {
		var body struct {
			Resources []json.RawMessage `json:"Resources"`
		}
		if err := c.do(ctx, http.MethodGet,
			"/scim2/Users?count=10&filter="+url.QueryEscape(filter), nil, &body); err != nil {
			return nil, err
		}
		for _, raw := range body.Resources {
			user, err := parseUser(raw)
			if err != nil {
				return nil, err
			}
			if user.InUserStore() {
				return &user, nil
			}
		}
	}
	return nil, nil
}

// How long Asgardeo is given to answer. Creating an account sends the
// invitation email before Asgardeo answers, which can take a while.
const (
	defaultReadTimeout  = 20 * time.Second
	defaultWriteTimeout = 60 * time.Second
)

// CreateUser creates the account and has Asgardeo email the person a link
// to set their own password. When Asgardeo already has the address, that
// account is returned with created=false and no email goes out.
func (c *Client) CreateUser(ctx context.Context, givenName, familyName, email string) (*User, bool, error) {
	started := time.Now()
	user, created, err := c.createUser(ctx, givenName, familyName, email)
	var ae *Error
	if err == nil || !errors.As(err, &ae) || !ae.Unanswered {
		return user, created, err
	}
	// No answer: Asgardeo may have created the account all the same. Look,
	// a few times, before calling it a failure - so a second attempt never
	// meets a half-made account, and an invitation that did go out is not
	// reported as failed.
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, false, err
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		found, findErr := c.FindByEmail(ctx, email)
		if findErr != nil {
			continue
		}
		if found != nil {
			// Made by this request if it appeared after the request started.
			return found, !found.Created.IsZero() && found.Created.After(started.Add(-time.Minute)), nil
		}
	}
	return nil, false, &Error{Status: ae.Status, Unanswered: true,
		Detail: ae.Detail + " No account was created; it is safe to try again."}
}

func (c *Client) createUser(ctx context.Context, givenName, familyName, email string) (*User, bool, error) {
	name := map[string]string{"givenName": givenName}
	if familyName != "" {
		name["familyName"] = familyName
	}
	var raw json.RawMessage
	err := c.do(ctx, http.MethodPost, "/scim2/Users", map[string]any{
		"schemas":  []string{userSchema, wso2Schema},
		"userName": UserStore + "/" + email,
		"name":     name,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		wso2Schema: map[string]any{"askPassword": true},
	}, &raw)
	if IsStatus(err, http.StatusConflict) {
		existing, findErr := c.FindByEmail(ctx, email)
		if findErr != nil {
			return nil, false, findErr
		}
		if existing != nil {
			return existing, false, nil
		}
	}
	if err != nil {
		return nil, false, err
	}
	user, err := parseUser(raw)
	return &user, true, err
}

// UpdateName changes the name Asgardeo holds.
func (c *Client) UpdateName(ctx context.Context, id, givenName, familyName string) error {
	return c.patch(ctx, "/scim2/Users/"+url.PathEscape(id), []map[string]any{{
		"op":    "replace",
		"value": map[string]any{"name": map[string]string{"givenName": givenName, "familyName": familyName}},
	}})
}

// SetLocked locks or unlocks the account: a locked account cannot sign in.
func (c *Client) SetLocked(ctx context.Context, id string, locked bool) error {
	return c.patch(ctx, "/scim2/Users/"+url.PathEscape(id), []map[string]any{{
		"op":    "replace",
		"value": map[string]any{wso2Schema: map[string]any{"accountLocked": locked}},
	}})
}

// DeleteUser removes the account; one that is already gone is fine.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/scim2/Users/"+url.PathEscape(id), nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// CreateGroup creates a group and returns its id.
func (c *Client) CreateGroup(ctx context.Context, displayName string) (string, error) {
	var body struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/scim2/Groups", map[string]any{
		"schemas":     []string{groupSchema},
		"displayName": displayName,
	}, &body)
	return body.ID, err
}

// AddGroupMember puts a user in a group.
func (c *Client) AddGroupMember(ctx context.Context, groupID, userID string) error {
	return c.patch(ctx, "/scim2/Groups/"+url.PathEscape(groupID), []map[string]any{{
		"op":    "add",
		"value": map[string]any{"members": []map[string]string{{"value": userID}}},
	}})
}

// RemoveGroupMember takes a user out of a group; not being in it is fine.
func (c *Client) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	err := c.patch(ctx, "/scim2/Groups/"+url.PathEscape(groupID), []map[string]any{{
		"op":   "remove",
		"path": fmt.Sprintf(`members[value eq "%s"]`, scimString(userID)),
	}})
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func (c *Client) patch(ctx context.Context, path string, operations []map[string]any) error {
	return c.do(ctx, http.MethodPatch, path, map[string]any{
		"schemas":    []string{patchSchema},
		"Operations": operations,
	}, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}

	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	limit := c.readTimeout
	if method != http.MethodGet {
		limit = c.writeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/scim+json, application/json")
	if in != nil {
		// SCIM endpoints take SCIM JSON; the rest of Asgardeo's APIs, plain JSON.
		if strings.HasPrefix(path, "/scim2/") {
			req.Header.Set("Content-Type", "application/scim+json")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	// Reads, and the changes that come out the same however often they are
	// made (replacing a value, deleting), are tried again after a dropped
	// connection; a create is not.
	resp, err := c.send(req, method != http.MethodPost)
	if err != nil {
		return unanswered(err, limit)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Detail: errorDetail(raw, resp.StatusCode)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("asgardeo: unreadable answer: %w", err)
		}
	}
	return nil
}

// accessToken is a client-credentials token, reused until a minute before
// it expires. Every scope the Hub can use is asked for; Asgardeo grants
// those the M2M application was authorized for.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Add(time.Minute).Before(c.tokenExpiry) {
		return c.token, nil
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {strings.Join(allScopes(), " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Asking for a token again is harmless.
	resp, err := c.send(req, true)
	if err != nil {
		return "", unanswered(err, c.readTimeout)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Status: resp.StatusCode, Detail: errorDetail(raw, resp.StatusCode)}
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.AccessToken == "" {
		return "", &Error{Status: http.StatusBadGateway, Detail: "Asgardeo issued no access token"}
	}
	if body.ExpiresIn <= 0 {
		body.ExpiresIn = 3600
	}
	c.token = body.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	c.granted = map[string]bool{}
	for _, scope := range strings.Fields(body.Scope) {
		c.granted[scope] = true
	}
	return c.token, nil
}

// unanswered describes a request Asgardeo gave no answer to.
func unanswered(err error, limit time.Duration) *Error {
	detail := "The connection to Asgardeo failed."
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		detail = fmt.Sprintf("Asgardeo did not answer within %d seconds.", int(limit.Seconds()))
	}
	return &Error{Status: http.StatusGatewayTimeout, Detail: detail, Unanswered: true}
}

// send makes the request; one that failed to get any answer (a dropped
// connection, not a timeout) is tried twice more when repeating it is safe.
func (c *Client) send(req *http.Request, repeatable bool) (*http.Response, error) {
	resp, err := c.http.Do(req)
	for attempt := 1; err != nil && repeatable && attempt < 3 && req.Context().Err() == nil; attempt++ {
		time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
		if req.GetBody != nil {
			if req.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		resp, err = c.http.Do(req)
	}
	return resp, err
}

// parseUser reads the parts of a SCIM user the Hub uses. Asgardeo returns
// emails as strings or objects, and booleans sometimes as strings.
func parseUser(raw json.RawMessage) (User, error) {
	var in struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
		Name     struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
		} `json:"name"`
		Emails []json.RawMessage `json:"emails"`
		Meta   struct {
			Created string `json:"created"`
		} `json:"meta"`
		WSO2 struct {
			AccountType   string `json:"userAccountType"`
			AccountState  string `json:"accountState"`
			AccountLocked any    `json:"accountLocked"`
		} `json:"urn:scim:wso2:schema"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return User{}, fmt.Errorf("asgardeo: unreadable user: %w", err)
	}

	user := User{
		ID:           in.ID,
		UserName:     in.UserName,
		GivenName:    in.Name.GivenName,
		FamilyName:   in.Name.FamilyName,
		AccountType:  in.WSO2.AccountType,
		AccountState: in.WSO2.AccountState,
	}
	switch locked := in.WSO2.AccountLocked.(type) {
	case bool:
		user.Locked = locked
	case string:
		user.Locked = strings.EqualFold(locked, "true")
	}
	if user.AccountState == "LOCKED" {
		user.Locked = true
	}
	if created, err := time.Parse(time.RFC3339Nano, in.Meta.Created); err == nil {
		user.Created = created
	}

	var fallback string
	for _, entry := range in.Emails {
		var plain string
		if json.Unmarshal(entry, &plain) == nil {
			if fallback == "" {
				fallback = plain
			}
			continue
		}
		var object struct {
			Value   string `json:"value"`
			Primary bool   `json:"primary"`
		}
		if json.Unmarshal(entry, &object) == nil && object.Value != "" {
			if object.Primary {
				user.Email = object.Value
			}
			if fallback == "" {
				fallback = object.Value
			}
		}
	}
	if user.Email == "" {
		user.Email = fallback
	}
	if user.Email == "" {
		user.Email = strings.TrimPrefix(user.UserName, UserStore+"/")
	}
	user.Email = strings.ToLower(user.Email)
	return user, nil
}

func errorDetail(raw []byte, status int) string {
	var body map[string]any
	if json.Unmarshal(raw, &body) == nil {
		for _, key := range []string{"detail", "error_description", "description", "error"} {
			if text, ok := body[key].(string); ok && text != "" {
				return text
			}
		}
	}
	return fmt.Sprintf("request failed (%d)", status)
}

func scimString(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}
