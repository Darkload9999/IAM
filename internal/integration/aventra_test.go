package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/zeit26/identity-hub/internal/store"
)

// TestAventraEndToEnd provisions into a running Aventra PM tool: the real
// SCIM receiver, the real database behind it. Asgardeo is still the
// stand-in, so nothing is created in the real organization.
//
//	AVENTRA_SCIM_URL=http://localhost:8080/api/v1/scim/v2
//	AVENTRA_SCIM_TOKEN=<the PM tool's SCIM_BEARER_TOKEN>
//
// It leaves one deactivated account behind in the PM tool, named
// hub-e2e-<time>@example.com.
func TestAventraEndToEnd(t *testing.T) {
	scimURL, token := os.Getenv("AVENTRA_SCIM_URL"), os.Getenv("AVENTRA_SCIM_TOKEN")
	if scimURL == "" || token == "" {
		t.Skip("AVENTRA_SCIM_URL and AVENTRA_SCIM_TOKEN are not set")
	}
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)

	var created struct {
		App store.Application `json:"app"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{
		"key": "aventra", "name": "Aventra PM", "scimUrl": scimURL, "scimToken": token,
	}, &created)
	appID := created.App.ID
	owner.must(200, "POST", "/api/apps/"+appID+"/test", nil, nil)

	var imported struct{ PermissionsAdded, RolesAdded int }
	owner.must(200, "POST", "/api/apps/"+appID+"/import", nil, &imported)
	if imported.PermissionsAdded < 20 || imported.RolesAdded < 5 {
		t.Fatalf("import from Aventra: %+v", imported)
	}
	role, perm := e.catalogIDs(owner, "DEVELOPER", "projects:create")
	member, _ := e.catalogIDs(owner, "MEMBER", "")
	_, usersRead := e.catalogIDs(owner, "", "users:read")

	email := fmt.Sprintf("hub-e2e-%d@example.com", time.Now().Unix())
	var onboarded struct {
		User store.User `json:"user"`
	}
	owner.must(201, "POST", "/api/users", map[string]any{"givenName": "Hub", "familyName": "Check", "email": email,
		"access": []map[string]any{{"appId": appID, "roleIds": []string{role}, "permissionIds": []string{perm}}}}, &onboarded)
	e.work()
	e.expectGrant(owner, onboarded.User.ID, "provisioned")

	got := aventraUser(t, scimURL, token, email)
	if !got.Active || got.role() != "DEVELOPER" || !slices.Equal(got.direct(), []string{"projects:create"}) ||
		got.ExternalID == "" || got.DisplayName != "Hub Check" {
		t.Fatalf("in Aventra after onboarding: %+v", got)
	}

	// Role taken away, two single permissions instead: MEMBER plus both.
	owner.must(200, "PUT", "/api/users/"+onboarded.User.ID+"/access/"+appID, map[string]any{
		"roleIds": []string{member}, "permissionIds": []string{perm, usersRead}}, nil)
	e.work()
	got = aventraUser(t, scimURL, token, email)
	if got.role() != "MEMBER" || !slices.Equal(got.direct(), []string{"projects:create", "users:read"}) {
		t.Fatalf("in Aventra after changing access: %+v", got)
	}

	// Suspended in the Hub: inactive in Aventra; restored: active again.
	owner.must(200, "POST", "/api/users/"+onboarded.User.ID+"/lock", nil, nil)
	e.work()
	if aventraUser(t, scimURL, token, email).Active {
		t.Fatal("suspension did not reach Aventra")
	}
	owner.must(200, "POST", "/api/users/"+onboarded.User.ID+"/unlock", nil, nil)
	e.work()
	if !aventraUser(t, scimURL, token, email).Active {
		t.Fatal("restoring did not reach Aventra")
	}

	// Access removed: deactivated in Aventra, the account itself kept.
	owner.must(204, "DELETE", "/api/users/"+onboarded.User.ID+"/access/"+appID, nil, nil)
	e.work()
	if got := aventraUser(t, scimURL, token, email); got.Active {
		t.Fatalf("after revoking: %+v", got)
	}
}

func (e *env) catalogIDs(b *browser, roleKey, permissionKey string) (roleID, permissionID string) {
	e.t.Helper()
	var catalog struct {
		Apps []struct {
			Permissions []store.Permission `json:"permissions"`
			Roles       []store.Role       `json:"roles"`
		} `json:"apps"`
	}
	b.must(200, "GET", "/api/catalog", nil, &catalog)
	for _, r := range catalog.Apps[0].Roles {
		if r.Key == roleKey {
			roleID = r.ID
		}
	}
	for _, p := range catalog.Apps[0].Permissions {
		if p.Key == permissionKey {
			permissionID = p.ID
		}
	}
	if (roleKey != "" && roleID == "") || (permissionKey != "" && permissionID == "") {
		e.t.Fatalf("catalog lacks %q / %q", roleKey, permissionKey)
	}
	return roleID, permissionID
}

func (e *env) expectGrant(b *browser, userID, status string) {
	e.t.Helper()
	var detail struct {
		Grants []store.Grant `json:"grants"`
	}
	b.must(200, "GET", "/api/users/"+userID, nil, &detail)
	if len(detail.Grants) != 1 || detail.Grants[0].SyncStatus != status {
		e.t.Fatalf("grant: %+v", detail.Grants)
	}
}

type aventraAccount struct {
	ID          string `json:"id"`
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
}

func (a aventraAccount) role() string {
	if len(a.Roles) == 0 {
		return ""
	}
	return a.Roles[0].Value
}

func (a aventraAccount) direct() []string {
	out := []string{}
	for _, e := range a.Entitlements {
		out = append(out, e.Value)
	}
	return out
}

// aventraUser reads the account straight from Aventra's SCIM endpoint.
func aventraUser(t *testing.T, scimURL, token, email string) aventraAccount {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET",
		scimURL+"/Users?filter="+url.QueryEscape(`userName eq "`+email+`"`), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list struct {
		Resources []aventraAccount `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil || len(list.Resources) != 1 {
		t.Fatalf("Aventra has no single account %s (status %d, %v)", email, resp.StatusCode, err)
	}
	return list.Resources[0]
}
