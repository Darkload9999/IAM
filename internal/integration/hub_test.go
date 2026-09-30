// Package integration runs the whole Hub - web server, service, worker and
// PostgreSQL - against a stand-in Asgardeo and a stand-in application (internal/testfakes):
// the tests never create or change anything in the real organization.
//
// It needs a database it may wipe: HUB_TEST_DATABASE_URL. Without one the
// tests are skipped.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeit26/identity-hub/internal/asgardeo"
	"github.com/zeit26/identity-hub/internal/db"
	"github.com/zeit26/identity-hub/internal/hub"
	"github.com/zeit26/identity-hub/internal/provisioning"
	"github.com/zeit26/identity-hub/internal/secrets"
	"github.com/zeit26/identity-hub/internal/store"
	"github.com/zeit26/identity-hub/internal/testfakes"
	"github.com/zeit26/identity-hub/internal/web"
)

type env struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	asgardeo *testfakes.Asgardeo
	app      *testfakes.App
	appURL   string
	hubURL   string
	svc      *hub.Service
	worker   *provisioning.Worker
	ownerID  string
}

func setup(t *testing.T) *env {
	t.Helper()
	url := os.Getenv("HUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("HUB_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	e := &env{t: t, ctx: ctx, pool: pool, asgardeo: testfakes.NewAsgardeo(), app: testfakes.NewApp()}
	asg := httptest.NewServer(e.asgardeo.Handler())
	t.Cleanup(asg.Close)
	e.asgardeo.BaseURL = asg.URL
	appServer := httptest.NewServer(e.app.Handler())
	t.Cleanup(appServer.Close)
	e.appURL = appServer.URL + "/scim/v2"

	e.ownerID = e.asgardeo.AddUser(testfakes.AsgardeoUser{UserName: "owner@zeit26.test", Email: "owner@zeit26.test",
		GivenName: "Olive", FamilyName: "Owner", AccountType: "Owner"})

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, _ := secrets.New(bytes.Repeat([]byte{7}, 32))
	st := store.New(pool)
	e.worker = provisioning.NewWorker(st, box, log)
	e.svc = hub.New(st, asgardeo.New(asg.URL, "m2m-client", "m2m-secret"), box, log, nil)

	hubServer := httptest.NewUnstartedServer(nil)
	e.hubURL = "http://" + hubServer.Listener.Addr().String()
	hubServer.Config.Handler = web.New(web.Options{
		PublicURL:  e.hubURL,
		SessionTTL: time.Hour,
		OIDC: web.OIDCSettings{Issuer: asg.URL + "/oauth2/token", ClientID: "hub-client",
			ClientSecret: "hub-secret", RedirectURL: e.hubURL + "/auth/callback"},
		UI: fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>dashboard</title>")}},
	}, e.svc, st, box, log)
	hubServer.Start()
	t.Cleanup(hubServer.Close)
	return e
}

// work runs the provisioning worker until nothing is due.
func (e *env) work() { e.worker.RunOnce(e.ctx) }

// ----------------------------------------------------------- the browser

type browser struct {
	e      *env
	client *http.Client
	csrf   string
}

// signIn goes through the whole sign-in as the Asgardeo account asgardeoID
// and returns the status of the page the browser lands on.
func (e *env) signIn(asgardeoID string) (*browser, int, string) {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	b := &browser{e: e, client: &http.Client{Jar: jar}}
	e.asgardeo.AutoLogin = asgardeoID
	resp, err := b.client.Get(e.hubURL + "/auth/login?return=/users")
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var me struct {
			CSRFToken string `json:"csrfToken"`
		}
		if b.call("GET", "/api/me", nil, &me) == http.StatusOK {
			b.csrf = me.CSRFToken
		}
	}
	return b, resp.StatusCode, string(body)
}

// call makes an API request as the dashboard would and decodes the answer.
func (b *browser) call(method, path string, in, out any) int {
	b.e.t.Helper()
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, b.e.hubURL+path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" {
		req.Header.Set("Origin", b.e.hubURL)
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			b.e.t.Fatalf("%s %s: %v in %s", method, path, err, raw)
		}
	}
	return resp.StatusCode
}

// must is call that fails the test on an unexpected status.
func (b *browser) must(want int, method, path string, in, out any) {
	b.e.t.Helper()
	var raw json.RawMessage
	got := b.call(method, path, in, &raw)
	if got != want {
		b.e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, got, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			b.e.t.Fatal(err)
		}
	}
}

// ------------------------------------------------------------------ tests

func TestSignInIsForAdminsOnly(t *testing.T) {
	e := setup(t)
	staffID := e.asgardeo.AddUser(testfakes.AsgardeoUser{Email: "staff@zeit26.test", GivenName: "Sam"})

	// Somebody who is not a Hub admin gets no session.
	b, status, body := e.signIn(staffID)
	if status != http.StatusForbidden || !strings.Contains(body, "not a Hub admin") {
		t.Fatalf("non-admin sign-in: %d %s", status, body)
	}
	if got := b.call("GET", "/api/me", nil, nil); got != http.StatusUnauthorized {
		t.Fatalf("non-admin /api/me: %d", got)
	}

	// The organization owner always is one - even on a first start, before
	// any sync has run.
	owner, status, body := e.signIn(e.ownerID)
	if status != http.StatusOK || !strings.Contains(body, "dashboard") {
		t.Fatalf("owner sign-in: %d %s", status, body)
	}
	var me struct {
		Email, Role string
	}
	owner.must(200, "GET", "/api/me", nil, &me)
	if me.Email != "owner@zeit26.test" || me.Role != "owner" {
		t.Fatalf("me = %+v", me)
	}

	// Pages redirect to sign-in when there is no session.
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := anon.Get(e.hubURL + "/users/123")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/auth/login?return=") {
		t.Fatalf("anonymous page: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestChangesNeedTheCSRFTokenAndOrigin(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)

	try := func(origin, token string) int {
		req, _ := http.NewRequest("POST", e.hubURL+"/api/sync", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
		resp, err := owner.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := try(e.hubURL, ""); got != http.StatusForbidden {
		t.Errorf("no token: %d", got)
	}
	if got := try(e.hubURL, "wrong"); got != http.StatusForbidden {
		t.Errorf("wrong token: %d", got)
	}
	if got := try("https://evil.example", owner.csrf); got != http.StatusForbidden {
		t.Errorf("foreign origin: %d", got)
	}
	if got := try(e.hubURL, owner.csrf); got != http.StatusOK {
		t.Errorf("proper request: %d", got)
	}
}

func TestOnboardProvisionAndOffboard(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)

	// An application that takes pushes, with permissions and a role.
	var created struct {
		App       store.Application `json:"app"`
		SCIMToken string            `json:"scimToken"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{
		"key": "pm-tool", "name": "PM Tool", "url": "https://pm.zeit26.test", "scimUrl": e.appURL,
	}, &created)
	if created.SCIMToken == "" || !created.App.HasSCIMToken {
		t.Fatalf("no SCIM token issued: %+v", created)
	}
	e.app.SetToken(created.SCIMToken)
	appID := created.App.ID

	var read, write struct {
		Permission store.Permission `json:"permission"`
	}
	owner.must(201, "POST", "/api/apps/"+appID+"/permissions", map[string]string{"key": "projects:read", "name": "Read projects"}, &read)
	owner.must(201, "POST", "/api/apps/"+appID+"/permissions", map[string]string{"key": "projects:write", "name": "Change projects"}, &write)
	var dev struct {
		Role store.Role `json:"role"`
	}
	owner.must(201, "POST", "/api/apps/"+appID+"/roles", map[string]any{
		"key": "DEVELOPER", "name": "Developer", "permissionIds": []string{read.Permission.ID, write.Permission.ID},
	}, &dev)

	// Onboarding: Asgardeo creates the account and sends the invite; the
	// application receives it with the role and its permissions.
	var onboarded struct {
		User       store.User `json:"user"`
		Invitation string     `json:"invitation"`
	}
	owner.must(201, "POST", "/api/users", map[string]any{
		"givenName": "Ada", "familyName": "Lovelace", "email": "Ada@Zeit26.test", "department": "Engineering",
		"access": []map[string]any{{"appId": appID, "roleIds": []string{dev.Role.ID}}},
	}, &onboarded)
	ada := onboarded.User
	remote := e.asgardeo.UserByEmail("ada@zeit26.test")
	if onboarded.Invitation != "SENT" || remote == nil || !remote.Invited || remote.UserName != "DEFAULT/ada@zeit26.test" {
		t.Fatalf("onboarding: %+v, asgardeo %+v", onboarded, remote)
	}

	e.work()
	got := e.app.User("ada@zeit26.test")
	if got == nil || !got.Active || !slices.Equal(got.Roles, []string{"DEVELOPER"}) ||
		!slices.Equal(got.Permissions, []string{"projects:read", "projects:write"}) ||
		got.Department != "Engineering" || got.ExternalID != remote.ID {
		t.Fatalf("app account after onboarding: %+v", got)
	}
	var detail struct {
		Grants []store.Grant `json:"grants"`
	}
	owner.must(200, "GET", "/api/users/"+ada.ID, nil, &detail)
	if len(detail.Grants) != 1 || detail.Grants[0].SyncStatus != "provisioned" || detail.Grants[0].RemoteID != got.ID {
		t.Fatalf("grant after provisioning: %+v", detail.Grants)
	}

	// Changing a role reaches everybody who holds it.
	owner.must(200, "PATCH", "/api/apps/"+appID+"/roles/"+dev.Role.ID, map[string]any{
		"name": "Developer", "permissionIds": []string{read.Permission.ID},
	}, nil)
	e.work()
	if got := e.app.User("ada@zeit26.test"); !slices.Equal(got.Permissions, []string{"projects:read"}) {
		t.Fatalf("permissions after role change: %v", got.Permissions)
	}

	// A direct permission on top of the role.
	owner.must(200, "PUT", "/api/users/"+ada.ID+"/access/"+appID, map[string]any{
		"roleIds": []string{dev.Role.ID}, "permissionIds": []string{write.Permission.ID},
	}, nil)
	e.work()
	if got := e.app.User("ada@zeit26.test"); !slices.Equal(got.Permissions, []string{"projects:read", "projects:write"}) {
		t.Fatalf("permissions with a direct grant: %v", got.Permissions)
	}

	// Suspending: locked in Asgardeo, inactive in the application.
	owner.must(200, "POST", "/api/users/"+ada.ID+"/lock", nil, nil)
	e.work()
	if !e.asgardeo.User(remote.ID).Locked || e.app.User("ada@zeit26.test").Active {
		t.Fatal("suspension did not reach Asgardeo and the application")
	}
	owner.must(200, "POST", "/api/users/"+ada.ID+"/unlock", nil, nil)
	e.work()
	if e.asgardeo.User(remote.ID).Locked || !e.app.User("ada@zeit26.test").Active {
		t.Fatal("restoring did not reach Asgardeo and the application")
	}

	// Revoking: deactivated in the application, not deleted; grant gone.
	owner.must(204, "DELETE", "/api/users/"+ada.ID+"/access/"+appID, nil, nil)
	e.work()
	if got := e.app.User("ada@zeit26.test"); got == nil || got.Active {
		t.Fatalf("after revoking: %+v", got)
	}
	owner.must(200, "GET", "/api/users/"+ada.ID, nil, &detail)
	if len(detail.Grants) != 0 {
		t.Fatalf("grant left after revoking: %+v", detail.Grants)
	}

	// Offboarding: deactivated everywhere, deleted from Asgardeo, kept here
	// as removed for the record.
	owner.must(200, "PUT", "/api/users/"+ada.ID+"/access/"+appID, map[string]any{"roleIds": []string{dev.Role.ID}}, nil)
	e.work()
	if !e.app.User("ada@zeit26.test").Active {
		t.Fatal("access given again did not reactivate the account")
	}
	owner.must(204, "DELETE", "/api/users/"+ada.ID, nil, nil)
	e.work()
	if e.asgardeo.User(remote.ID) != nil || e.app.User("ada@zeit26.test").Active {
		t.Fatal("offboarding left the account active somewhere")
	}
	var after struct {
		User store.User `json:"user"`
	}
	owner.must(200, "GET", "/api/users/"+ada.ID, nil, &after)
	if after.User.RemovedAt == nil {
		t.Fatal("offboarded user not marked removed")
	}

	// Every step is in the audit log.
	var audit struct {
		Events []store.AuditEvent `json:"events"`
	}
	owner.must(200, "GET", "/api/audit?target="+ada.ID, nil, &audit)
	var actions []string
	for _, ev := range audit.Events {
		actions = append(actions, ev.Action)
	}
	for _, want := range []string{"user.create", "access.set", "user.lock", "user.unlock", "access.revoke", "user.delete"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit log lacks %s: %v", want, actions)
		}
	}
}

func TestNoAccountIsCreatedJustToBeSwitchedOff(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)
	var created struct {
		App       store.Application `json:"app"`
		SCIMToken string            `json:"scimToken"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{"key": "wiki", "name": "Wiki", "scimUrl": e.appURL}, &created)
	e.app.SetToken(created.SCIMToken)

	var onboarded struct {
		User store.User `json:"user"`
	}
	owner.must(201, "POST", "/api/users", map[string]any{"givenName": "Bo", "email": "bo@zeit26.test",
		"access": []map[string]any{{"appId": created.App.ID}}}, &onboarded)
	// Revoked before the worker ever pushed it.
	owner.must(204, "DELETE", "/api/users/"+onboarded.User.ID+"/access/"+created.App.ID, nil, nil)
	e.work()
	if e.app.Count() != 0 {
		t.Fatalf("the application got %d account(s)", e.app.Count())
	}
}

func TestFailedPushesAreRetriedOrParked(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)
	var created struct {
		App       store.Application `json:"app"`
		SCIMToken string            `json:"scimToken"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{"key": "crm", "name": "CRM", "scimUrl": e.appURL}, &created)
	e.app.SetToken(created.SCIMToken)

	// A temporary failure: tried again later.
	e.app.FailWith(http.StatusServiceUnavailable)
	owner.must(201, "POST", "/api/users", map[string]any{"givenName": "Cy", "email": "cy@zeit26.test",
		"access": []map[string]any{{"appId": created.App.ID}}}, nil)
	e.work()
	var jobs struct {
		Jobs []store.Job `json:"jobs"`
	}
	owner.must(200, "GET", "/api/jobs?status=pending", nil, &jobs)
	if len(jobs.Jobs) != 1 || jobs.Jobs[0].Attempts != 1 || !jobs.Jobs[0].NextRunAt.After(time.Now()) {
		t.Fatalf("temporary failure not scheduled for retry: %+v", jobs.Jobs)
	}

	// A permanent refusal: parked as failed until an admin retries it.
	e.app.FailWith(http.StatusBadRequest)
	if _, err := e.pool.Exec(e.ctx, `UPDATE provisioning_jobs SET next_run_at = now()`); err != nil {
		t.Fatal(err)
	}
	e.work()
	owner.must(200, "GET", "/api/jobs?status=failed", nil, &jobs)
	if len(jobs.Jobs) != 1 || !strings.Contains(jobs.Jobs[0].LastError, "400") {
		t.Fatalf("permanent failure not parked: %+v", jobs.Jobs)
	}

	e.app.FailWith(0)
	owner.must(204, "POST", "/api/jobs/"+jobs.Jobs[0].ID+"/retry", nil, nil)
	e.work()
	if got := e.app.User("cy@zeit26.test"); got == nil || !got.Active {
		t.Fatalf("retry did not provision: %+v", got)
	}
}

func TestSyncCarriesConsoleChangesToApplications(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)
	var created struct {
		App       store.Application `json:"app"`
		SCIMToken string            `json:"scimToken"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{"key": "pm", "name": "PM", "scimUrl": e.appURL}, &created)
	e.app.SetToken(created.SCIMToken)

	// Somebody created in the Asgardeo console shows up after a sync.
	consoleID := e.asgardeo.AddUser(testfakes.AsgardeoUser{Email: "dee@zeit26.test", GivenName: "Dee", FamilyName: "Old"})
	owner.must(200, "POST", "/api/sync", nil, nil)
	var list struct {
		Users []store.User `json:"users"`
	}
	owner.must(200, "GET", "/api/users?search=dee", nil, &list)
	if len(list.Users) != 1 {
		t.Fatalf("console user not synced: %+v", list.Users)
	}
	dee := list.Users[0]
	owner.must(200, "PUT", "/api/users/"+dee.ID+"/access/"+created.App.ID, map[string]any{}, nil)
	e.work()

	// Renamed and locked in the console: the application follows.
	e.asgardeo.Edit(consoleID, func(u *testfakes.AsgardeoUser) { u.FamilyName = "New"; u.Locked = true; u.State = "LOCKED" })
	if err := e.svc.SyncUsers(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.work()
	if got := e.app.User("dee@zeit26.test"); got.DisplayName != "Dee New" || got.Active {
		t.Fatalf("console change not carried over: %+v", got)
	}

	// Deleted in the console: deactivated in the application.
	e.asgardeo.Edit(consoleID, func(u *testfakes.AsgardeoUser) { u.Locked = false })
	_ = e.svc.SyncUsers(e.ctx)
	e.work()
	e.asgardeo.Remove(consoleID)
	_ = e.svc.SyncUsers(e.ctx)
	e.work()
	if got := e.app.User("dee@zeit26.test"); got.Active {
		t.Fatal("account deleted in Asgardeo still active in the application")
	}
	owner.must(200, "GET", "/api/users?status=removed", nil, &list)
	if len(list.Users) != 1 || list.Users[0].ID != dee.ID {
		t.Fatalf("removed user not listed as removed: %+v", list.Users)
	}
}

func TestOwnerAppointsAdmins(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)
	benID := e.asgardeo.AddUser(testfakes.AsgardeoUser{Email: "ben@zeit26.test", GivenName: "Ben"})
	owner.must(200, "POST", "/api/sync", nil, nil)

	var added struct {
		User store.User `json:"user"`
	}
	owner.must(201, "POST", "/api/admins", map[string]string{"email": "ben@zeit26.test"}, &added)

	ben, status, _ := e.signIn(benID)
	if status != http.StatusOK {
		t.Fatalf("appointed admin cannot sign in: %d", status)
	}
	var me struct{ Role string }
	ben.must(200, "GET", "/api/me", nil, &me)
	if me.Role != "admin" {
		t.Fatalf("role = %q", me.Role)
	}
	// Only the owner appoints.
	ben.must(403, "POST", "/api/admins", map[string]string{"email": "owner@zeit26.test"}, nil)
	// Nobody can suspend the owner from the Hub.
	var ownerUser struct {
		Users []store.User `json:"users"`
	}
	ben.must(200, "GET", "/api/users?type=Owner", nil, &ownerUser)
	ben.must(409, "POST", "/api/users/"+ownerUser.Users[0].ID+"/lock", nil, nil)

	// An appointment belongs to the account, not to an address: another
	// account that takes Ben's address gets nothing.
	impostorID := e.asgardeo.AddUser(testfakes.AsgardeoUser{UserName: "DEFAULT/imp", Email: "ben@zeit26.test", GivenName: "Imp"})
	if _, status, _ := e.signIn(impostorID); status != http.StatusForbidden {
		t.Fatalf("an account sharing an admin's address signed in: %d", status)
	}

	// Withdrawn: Ben's very next request is refused.
	owner.must(204, "DELETE", "/api/admins/"+added.User.ID, nil, nil)
	if got := ben.call("GET", "/api/me", nil, nil); got != http.StatusForbidden {
		t.Fatalf("withdrawn admin still in: %d", got)
	}
}

// Asgardeo lets the owner sign in to applications only through a second
// account in the organization's user store, with the same username.
func TestOwnerSignsInWithTheirOrganizationAccount(t *testing.T) {
	e := setup(t)
	twinID := e.asgardeo.AddUser(testfakes.AsgardeoUser{UserName: "DEFAULT/owner@zeit26.test",
		Email: "owner@zeit26.test", GivenName: "Olive"})
	twin, status, _ := e.signIn(twinID)
	if status != http.StatusOK {
		t.Fatalf("owner's organization account refused: %d", status)
	}
	var me struct{ Role string }
	twin.must(200, "GET", "/api/me", nil, &me)
	if me.Role != "owner" {
		t.Fatalf("role = %q", me.Role)
	}

	// Same address, different username: not the owner.
	otherID := e.asgardeo.AddUser(testfakes.AsgardeoUser{UserName: "DEFAULT/olive", Email: "owner@zeit26.test"})
	if _, status, _ := e.signIn(otherID); status != http.StatusForbidden {
		t.Fatalf("an account sharing the owner's address signed in: %d", status)
	}

	// An appointed admin cannot lock the owner out.
	benID := e.asgardeo.AddUser(testfakes.AsgardeoUser{Email: "ben@zeit26.test", GivenName: "Ben"})
	twin.must(200, "POST", "/api/sync", nil, nil)
	twin.must(201, "POST", "/api/admins", map[string]string{"email": "ben@zeit26.test"}, nil)
	ben, _, _ := e.signIn(benID)
	var list struct {
		Users []store.User `json:"users"`
	}
	ben.must(200, "GET", "/api/users?search=olive", nil, &list)
	for _, u := range list.Users {
		if u.Username == "DEFAULT/owner@zeit26.test" {
			ben.must(409, "POST", "/api/users/"+u.ID+"/lock", nil, nil)
			ben.must(409, "DELETE", "/api/users/"+u.ID, nil, nil)
			return
		}
	}
	t.Fatal("owner's organization account not listed")
}

// An application that issued its own token: registered with it, checked,
// and its roles and permissions imported - then a person given an imported
// role plus a single extra permission gets exactly those.
func TestConnectAndImportFromApplication(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)
	const appToken = "token-issued-by-the-application-0123456789"
	e.app.SetToken(appToken)
	e.app.Catalog = map[string]any{
		"permissions": []map[string]string{
			{"key": "projects:read", "name": "View projects"},
			{"key": "projects:create", "name": "Create projects"},
			{"key": "work:read", "name": "View work"},
		},
		"roles": []map[string]any{
			{"key": "DEVELOPER", "name": "Developer", "permissions": []string{"projects:read", "work:read"}},
			{"key": "MEMBER", "name": "Member", "permissions": []string{}},
		},
	}

	var created struct {
		App       store.Application `json:"app"`
		SCIMToken string            `json:"scimToken"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{
		"key": "aventra", "name": "Aventra", "scimUrl": e.appURL, "scimToken": appToken,
	}, &created)
	if created.SCIMToken != "" {
		t.Fatal("a token the application issued was echoed back")
	}
	appID := created.App.ID
	owner.must(200, "POST", "/api/apps/"+appID+"/test", nil, nil)

	var result struct {
		PermissionsAdded, RolesAdded, RolesUpdated int
	}
	owner.must(200, "POST", "/api/apps/"+appID+"/import", nil, &result)
	if result.PermissionsAdded != 3 || result.RolesAdded != 2 {
		t.Fatalf("import: %+v", result)
	}
	// Importing again changes nothing new.
	owner.must(200, "POST", "/api/apps/"+appID+"/import", nil, &result)
	if result.PermissionsAdded != 0 || result.RolesAdded != 0 || result.RolesUpdated != 2 {
		t.Fatalf("second import: %+v", result)
	}

	var catalog struct {
		Apps []struct {
			ID          string             `json:"id"`
			Permissions []store.Permission `json:"permissions"`
			Roles       []store.Role       `json:"roles"`
		} `json:"apps"`
	}
	owner.must(200, "GET", "/api/catalog", nil, &catalog)
	var developerID, createID string
	for _, r := range catalog.Apps[0].Roles {
		if r.Key == "DEVELOPER" {
			developerID = r.ID
		}
	}
	for _, p := range catalog.Apps[0].Permissions {
		if p.Key == "projects:create" {
			createID = p.ID
		}
	}

	owner.must(201, "POST", "/api/users", map[string]any{"givenName": "Eve", "email": "eve@zeit26.test",
		"access": []map[string]any{{"appId": appID, "roleIds": []string{developerID}, "permissionIds": []string{createID}}}}, nil)
	e.work()
	got := e.app.User("eve@zeit26.test")
	if got == nil || !slices.Equal(got.Roles, []string{"DEVELOPER"}) ||
		!slices.Equal(got.Permissions, []string{"projects:create", "projects:read", "work:read"}) {
		t.Fatalf("pushed: %+v", got)
	}

	// A wrong token is caught by the connection test.
	e.app.SetToken("the-application-changed-its-token-000000")
	owner.must(502, "POST", "/api/apps/"+appID+"/test", nil, nil)
}

func TestSignOut(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)
	var out struct{ Redirect string }
	owner.must(200, "POST", "/auth/logout", nil, &out)
	if !strings.Contains(out.Redirect, "/oidc/logout") || !strings.Contains(out.Redirect, "id_token_hint=") {
		t.Fatalf("sign-out redirect: %q", out.Redirect)
	}
	resp, err := owner.client.Get(out.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "signed out") {
		t.Fatalf("did not land on the signed-out page: %s", body)
	}
	if got := owner.call("GET", "/api/me", nil, nil); got != http.StatusUnauthorized {
		t.Fatalf("session survived sign-out: %d", got)
	}
}
