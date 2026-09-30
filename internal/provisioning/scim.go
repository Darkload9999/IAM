// Package provisioning brings each application's copy of a person in line
// with the Hub: it pushes accounts, roles and permissions to the
// application's SCIM 2.0 endpoint, and deactivates them there.
package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeit26/identity-hub/internal/store"
)

// HubSchema is the Hub's extension to the SCIM user: everything an
// application may want beyond the core attributes.
const HubSchema = "urn:zeit26:params:scim:schemas:extension:hub:2.0:User"

const coreSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// PushError is an application's refusal. Permanent ones (a 4xx other than
// 408 and 429) are not retried: somebody has to fix the cause first.
type PushError struct {
	Status int
	Detail string
}

func (e *PushError) Error() string {
	if e.Status == 0 {
		return e.Detail
	}
	return fmt.Sprintf("application answered %d: %s", e.Status, e.Detail)
}

func (e *PushError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != 408 && e.Status != 429
}

type scimClient struct {
	http *http.Client
}

func newSCIMClient() *scimClient {
	return &scimClient{http: &http.Client{Timeout: 20 * time.Second}}
}

// UserResource is the SCIM user the Hub sends.
func UserResource(v store.ProvisioningView, active bool) map[string]any {
	u := v.User
	formatted := strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	if formatted == "" {
		formatted = u.Email
	}

	roles := []map[string]any{}
	for _, r := range v.Roles {
		roles = append(roles, map[string]any{"value": r.Key, "display": r.Name})
	}
	entitlements := []map[string]any{}
	permissionKeys := []string{}
	for _, p := range v.Permissions {
		entitlements = append(entitlements, map[string]any{"value": p.Key, "display": p.Name})
		permissionKeys = append(permissionKeys, p.Key)
	}

	return map[string]any{
		"schemas":     []string{coreSchema, HubSchema},
		"externalId":  u.AsgardeoID,
		"userName":    u.Email,
		"displayName": formatted,
		"name": map[string]any{
			"givenName":  u.GivenName,
			"familyName": u.FamilyName,
			"formatted":  formatted,
		},
		"emails":       []map[string]any{{"value": u.Email, "primary": true, "type": "work"}},
		"active":       active,
		"roles":        roles,
		"entitlements": entitlements,
		HubSchema: map[string]any{
			"asgardeoUserId": u.AsgardeoID,
			"department":     u.Department,
			"permissions":    permissionKeys,
		},
	}
}

// upsert creates the account in the application or replaces it there, and
// returns the id the application knows it by.
func (c *scimClient) upsert(ctx context.Context, baseURL, token, remoteID string, resource map[string]any) (string, error) {
	userName, _ := resource["userName"].(string)

	if remoteID == "" {
		found, err := c.findByUserName(ctx, baseURL, token, userName)
		if err != nil {
			return "", err
		}
		remoteID = found
	}

	if remoteID != "" {
		var out struct {
			ID string `json:"id"`
		}
		err := c.do(ctx, http.MethodPut, baseURL+"/Users/"+url.PathEscape(remoteID), token, resource, &out)
		if pe, ok := err.(*PushError); ok && pe.Status == http.StatusNotFound {
			// Removed in the application since: create it again.
			remoteID = ""
		} else if err != nil {
			return "", err
		} else {
			if out.ID != "" {
				return out.ID, nil
			}
			return remoteID, nil
		}
	}

	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, baseURL+"/Users", token, resource, &out)
	if pe, ok := err.(*PushError); ok && pe.Status == http.StatusConflict {
		// Created meanwhile, or already there under this userName.
		found, findErr := c.findByUserName(ctx, baseURL, token, userName)
		if findErr != nil {
			return "", findErr
		}
		if found == "" {
			return "", err
		}
		return c.upsert(ctx, baseURL, token, found, resource)
	}
	if err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", &PushError{Status: http.StatusBadGateway, Detail: "the application answered without an id"}
	}
	return out.ID, nil
}

// deactivate marks the account inactive in the application, if it has one.
// An account the application never received is left alone - not created
// just to be switched off.
func (c *scimClient) deactivate(ctx context.Context, baseURL, token, remoteID string, resource map[string]any) error {
	if remoteID == "" {
		userName, _ := resource["userName"].(string)
		found, err := c.findByUserName(ctx, baseURL, token, userName)
		if err != nil || found == "" {
			return err
		}
		remoteID = found
	}
	resource["active"] = false
	err := c.do(ctx, http.MethodPut, baseURL+"/Users/"+url.PathEscape(remoteID), token, resource, nil)
	if pe, ok := err.(*PushError); ok && pe.Status == http.StatusNotFound {
		return nil
	}
	return err
}

func (c *scimClient) findByUserName(ctx context.Context, baseURL, token, userName string) (string, error) {
	filter := fmt.Sprintf(`userName eq "%s"`, strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(userName))
	var out struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := c.do(ctx, http.MethodGet, baseURL+"/Users?filter="+url.QueryEscape(filter), token, nil, &out); err != nil {
		return "", err
	}
	if len(out.Resources) > 0 {
		return out.Resources[0].ID, nil
	}
	return "", nil
}

func (c *scimClient) do(ctx context.Context, method, target, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return &PushError{Detail: "bad SCIM URL: " + err.Error()}
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return &PushError{Detail: "the application could not be reached: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 300 {
		detail := strings.TrimSpace(string(raw))
		var scimErr map[string]any
		if json.Unmarshal(raw, &scimErr) == nil {
			for _, key := range []string{"detail", "message", "error"} {
				if text, ok := scimErr[key].(string); ok && text != "" {
					detail = text
					break
				}
			}
		}
		if len(detail) > 300 {
			detail = detail[:300]
		}
		if detail == "" {
			detail = http.StatusText(resp.StatusCode)
		}
		return &PushError{Status: resp.StatusCode, Detail: detail}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return &PushError{Status: http.StatusBadGateway, Detail: "unreadable answer from the application"}
		}
	}
	return nil
}
