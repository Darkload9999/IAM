package provisioning

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/zeit26/identity-hub/internal/store"
	"github.com/zeit26/identity-hub/internal/testfakes"
)

func view() store.ProvisioningView {
	return store.ProvisioningView{
		User:        store.User{AsgardeoID: "a-1", Email: "ada@x.io", GivenName: "Ada", FamilyName: "L", Department: "Eng"},
		Roles:       []store.Role{{Key: "DEVELOPER", Name: "Developer"}},
		Permissions: []store.Permission{{Key: "projects:read", Name: "Read"}},
	}
}

func TestUserResource(t *testing.T) {
	r := UserResource(view(), true)
	if r["userName"] != "ada@x.io" || r["externalId"] != "a-1" || r["active"] != true || r["displayName"] != "Ada L" {
		t.Fatalf("core attributes: %+v", r)
	}
	ext := r[HubSchema].(map[string]any)
	if ext["department"] != "Eng" || ext["permissions"].([]string)[0] != "projects:read" {
		t.Fatalf("extension: %+v", ext)
	}
}

func TestPermanent(t *testing.T) {
	for status, want := range map[int]bool{0: false, 400: true, 401: true, 404: true, 408: false, 429: false, 500: false, 503: false} {
		if got := (&PushError{Status: status}).Permanent(); got != want {
			t.Errorf("status %d: permanent = %v", status, got)
		}
	}
}

func TestUpsertAndDeactivate(t *testing.T) {
	app := testfakes.NewApp()
	app.SetToken("t")
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	c, ctx, base := newSCIMClient(), context.Background(), srv.URL+"/scim/v2"

	id, err := c.upsert(ctx, base, "t", "", UserResource(view(), true))
	if err != nil || id == "" {
		t.Fatalf("create: %q %v", id, err)
	}
	// Without the remote id (lost), the account is found by userName, not duplicated.
	again, err := c.upsert(ctx, base, "t", "", UserResource(view(), true))
	if err != nil || again != id || app.Count() != 1 {
		t.Fatalf("second push: %q %v count=%d", again, err, app.Count())
	}
	if err := c.deactivate(ctx, base, "t", id, UserResource(view(), true)); err != nil || app.User("ada@x.io").Active {
		t.Fatalf("deactivate: %v", err)
	}
	// Never pushed: nothing is created just to be switched off.
	other := view()
	other.User.Email = "new@x.io"
	if err := c.deactivate(ctx, base, "t", "", UserResource(other, true)); err != nil || app.Count() != 1 {
		t.Fatalf("deactivating an unknown account: %v count=%d", err, app.Count())
	}
	if _, err := c.upsert(ctx, base, "wrong", "", UserResource(view(), true)); err == nil || !err.(*PushError).Permanent() {
		t.Fatalf("wrong token: %v", err)
	}
}
