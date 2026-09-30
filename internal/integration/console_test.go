package integration

// The Asgardeo console through the Hub: groups, roles, applications,
// sessions, password resets and security policies - each only once the M2M
// application is authorized for it, and each within the Hub's own rules.

import (
	"slices"
	"testing"

	"github.com/zeit26/identity-hub/internal/asgardeo"
	"github.com/zeit26/identity-hub/internal/hub"
	"github.com/zeit26/identity-hub/internal/store"
	"github.com/zeit26/identity-hub/internal/testfakes"
)

// person puts an account in the stand-in Asgardeo and syncs it into the
// Hub; it answers with the Hub's id and the Asgardeo id.
func (e *env) person(owner *browser, email, given string) (string, string) {
	e.t.Helper()
	asgardeoID := e.asgardeo.AddUser(testfakes.AsgardeoUser{Email: email, GivenName: given})
	owner.must(200, "POST", "/api/sync", nil, nil)
	var found struct {
		Users []store.User `json:"users"`
	}
	owner.must(200, "GET", "/api/users?search="+email, nil, &found)
	if len(found.Users) != 1 {
		e.t.Fatalf("%s not synced: %+v", email, found.Users)
	}
	return found.Users[0].ID, asgardeoID
}

func (e *env) appointAdmin(owner *browser, email string) *browser {
	e.t.Helper()
	_, asgardeoID := e.person(owner, email, "Admin")
	owner.must(201, "POST", "/api/admins", map[string]string{"email": email}, nil)
	admin, status, _ := e.signIn(asgardeoID)
	if status != 200 {
		e.t.Fatalf("admin sign-in: %d", status)
	}
	return admin
}

func TestConsoleNeedsAuthorizationInAsgardeo(t *testing.T) {
	e := setup(t)
	owner, _, _ := e.signIn(e.ownerID)

	var caps struct {
		Modules []asgardeo.Capability `json:"modules"`
	}
	owner.must(200, "GET", "/api/asgardeo/capabilities", nil, &caps)
	enabled := map[string]bool{}
	for _, m := range caps.Modules {
		enabled[m.Key] = m.Enabled
		if !m.Enabled && len(m.Missing) == 0 {
			t.Fatalf("%s disabled but nothing missing", m.Key)
		}
	}
	if !enabled["users"] || enabled["groups"] || enabled["roles"] || enabled["sessions"] || enabled["security"] {
		t.Fatalf("capabilities: %+v", enabled)
	}

	var refused struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if got := owner.call("GET", "/api/asgardeo/roles", nil, &refused); got != 403 || refused.Error.Code != "NOT_AUTHORIZED" {
		t.Fatalf("roles without authorization: %d %+v", got, refused)
	}

	// Granted in Asgardeo: shown at once when asked to look again.
	e.asgardeo.GroupsAuthorized, e.asgardeo.ConsoleAuthorized = true, true
	owner.must(200, "GET", "/api/asgardeo/capabilities?refresh=1", nil, &caps)
	for _, m := range caps.Modules {
		if !m.Enabled {
			t.Fatalf("%s still disabled after authorization", m.Key)
		}
	}
}

func TestConsoleGroups(t *testing.T) {
	e := setup(t)
	e.asgardeo.GroupsAuthorized = true
	owner, _, _ := e.signIn(e.ownerID)
	adaID, adaAsgardeo := e.person(owner, "ada@zeit26.test", "Ada")

	var created struct {
		Group hub.GroupView `json:"group"`
	}
	owner.must(201, "POST", "/api/asgardeo/groups", map[string]string{"name": "Engineering"}, &created)
	id := created.Group.ID

	var got struct {
		Group hub.GroupView `json:"group"`
	}
	owner.must(200, "PUT", "/api/asgardeo/groups/"+id+"/members/"+adaID, nil, &got)
	if len(got.Group.Members) != 1 || got.Group.Members[0].UserID != adaID || got.Group.Members[0].Email != "ada@zeit26.test" {
		t.Fatalf("members: %+v", got.Group.Members)
	}
	if members := e.asgardeo.GroupMembers(id); !slices.Equal(members, []string{adaAsgardeo}) {
		t.Fatalf("in Asgardeo: %v", members)
	}

	owner.must(200, "PATCH", "/api/asgardeo/groups/"+id, map[string]string{"name": "Platform"}, &got)
	if name, _ := e.asgardeo.Group(id); name != "Platform" || got.Group.Name != "Platform" {
		t.Fatalf("rename: %q %q", name, got.Group.Name)
	}

	var list struct {
		Groups []hub.GroupView `json:"groups"`
	}
	owner.must(200, "GET", "/api/asgardeo/groups", nil, &list)
	if len(list.Groups) != 1 || list.Groups[0].Name != "Platform" {
		t.Fatalf("list: %+v", list.Groups)
	}

	owner.must(200, "DELETE", "/api/asgardeo/groups/"+id+"/members/"+adaID, nil, &got)
	if len(e.asgardeo.GroupMembers(id)) != 0 {
		t.Fatal("member not removed in Asgardeo")
	}
	owner.must(204, "DELETE", "/api/asgardeo/groups/"+id, nil, nil)
	if _, exists := e.asgardeo.Group(id); exists {
		t.Fatal("group not deleted in Asgardeo")
	}

	// An application's access group follows access given in the Hub: it is
	// not edited here.
	var app struct {
		App store.Application `json:"app"`
	}
	owner.must(201, "POST", "/api/apps", map[string]string{"key": "wiki", "name": "Wiki"}, &app)
	owner.must(200, "POST", "/api/apps/"+app.App.ID+"/group", nil, &app)
	groupID := app.App.AsgardeoGroupID
	owner.must(409, "PUT", "/api/asgardeo/groups/"+groupID+"/members/"+adaID, nil, nil)
	owner.must(409, "PATCH", "/api/asgardeo/groups/"+groupID, map[string]string{"name": "x"}, nil)
	owner.must(409, "DELETE", "/api/asgardeo/groups/"+groupID, nil, nil)
	owner.must(200, "GET", "/api/asgardeo/groups", nil, &list)
	if len(list.Groups) != 1 || list.Groups[0].AppName != "Wiki" {
		t.Fatalf("access group not marked: %+v", list.Groups)
	}

	var audit struct {
		Events []store.AuditEvent `json:"events"`
	}
	owner.must(200, "GET", "/api/audit?target="+id, nil, &audit)
	if len(audit.Events) < 4 {
		t.Fatalf("group changes not audited: %d events", len(audit.Events))
	}
}

func TestConsoleRoles(t *testing.T) {
	e := setup(t)
	e.asgardeo.GroupsAuthorized, e.asgardeo.ConsoleAuthorized = true, true
	owner, _, _ := e.signIn(e.ownerID)
	adaID, adaAsgardeo := e.person(owner, "ada@zeit26.test", "Ada")

	var list struct {
		Roles []hub.RoleView `json:"roles"`
	}
	owner.must(200, "GET", "/api/asgardeo/roles", nil, &list)
	var adminRole hub.RoleView
	for _, r := range list.Roles {
		if r.Name == "Administrator" {
			adminRole = r
		}
	}
	if !adminRole.System || len(adminRole.Permissions) == 0 {
		t.Fatalf("Administrator role: %+v", adminRole)
	}
	owner.must(409, "DELETE", "/api/asgardeo/roles/"+adminRole.ID, nil, nil)

	var created struct {
		Role hub.RoleView `json:"role"`
	}
	owner.must(201, "POST", "/api/asgardeo/roles", map[string]string{"name": "Auditor"}, &created)
	roleID := created.Role.ID

	owner.must(200, "PUT", "/api/asgardeo/roles/"+roleID+"/users/"+adaID, nil, &created)
	if len(created.Role.Users) != 1 || created.Role.Users[0].UserID != adaID {
		t.Fatalf("role users: %+v", created.Role.Users)
	}
	if got := e.asgardeo.RoleUsers(roleID); !slices.Equal(got, []string{adaAsgardeo}) {
		t.Fatalf("in Asgardeo: %v", got)
	}
	owner.must(400, "PUT", "/api/asgardeo/roles/"+roleID+"/robots/"+adaID, nil, nil)

	// Organization roles are the owner's to hand out.
	admin := e.appointAdmin(owner, "ben@zeit26.test")
	admin.must(200, "GET", "/api/asgardeo/roles", nil, nil)
	admin.must(403, "PUT", "/api/asgardeo/roles/"+roleID+"/users/"+adaID, nil, nil)
	admin.must(403, "POST", "/api/asgardeo/roles", map[string]string{"name": "Mine"}, nil)

	owner.must(200, "DELETE", "/api/asgardeo/roles/"+roleID+"/users/"+adaID, nil, &created)
	if len(e.asgardeo.RoleUsers(roleID)) != 0 {
		t.Fatal("assignment not removed in Asgardeo")
	}
	owner.must(204, "DELETE", "/api/asgardeo/roles/"+roleID, nil, nil)
	owner.must(404, "GET", "/api/asgardeo/roles/"+roleID, nil, nil)
}

func TestConsoleApplications(t *testing.T) {
	e := setup(t)
	e.asgardeo.ConsoleAuthorized = true
	owner, _, _ := e.signIn(e.ownerID)

	var list struct {
		Applications []hub.ConsoleApp `json:"applications"`
	}
	owner.must(200, "GET", "/api/asgardeo/applications", nil, &list)
	if len(list.Applications) != 2 || list.Applications[0].Name != "Aventra PM" {
		t.Fatalf("applications: %+v", list.Applications)
	}

	// Registered in the Hub under the same name: linked.
	owner.must(201, "POST", "/api/apps", map[string]string{"key": "aventra", "name": "Aventra PM"}, nil)
	var one struct {
		Application hub.ConsoleApp `json:"application"`
	}
	owner.must(200, "GET", "/api/asgardeo/applications/app-1", nil, &one)
	want := []string{"https://pm.example.com/api/auth/callback", "http://localhost:3000/api/auth/callback"}
	if !slices.Equal(one.Application.RedirectURLs, want) || one.Application.ClientID != "aventra-client" || one.Application.HubAppID == "" {
		t.Fatalf("application: %+v", one.Application)
	}
	owner.must(404, "GET", "/api/asgardeo/applications/nope", nil, nil)
}

func TestSessionsAndPasswordReset(t *testing.T) {
	e := setup(t)
	e.asgardeo.ConsoleAuthorized = true
	owner, _, _ := e.signIn(e.ownerID)
	adaID, adaAsgardeo := e.person(owner, "ada@zeit26.test", "Ada")

	first := e.asgardeo.AddSession(adaAsgardeo, "Aventra PM")
	e.asgardeo.AddSession(adaAsgardeo, "Wiki")

	var sessions struct {
		Sessions []asgardeo.Session `json:"sessions"`
	}
	owner.must(200, "GET", "/api/users/"+adaID+"/sessions", nil, &sessions)
	if len(sessions.Sessions) != 2 || sessions.Sessions[0].LoginTime.IsZero() || sessions.Sessions[0].IP == "" {
		t.Fatalf("sessions: %+v", sessions.Sessions)
	}
	owner.must(204, "DELETE", "/api/users/"+adaID+"/sessions/"+first, nil, nil)
	if n := e.asgardeo.SessionCount(adaAsgardeo); n != 1 {
		t.Fatalf("after ending one: %d", n)
	}
	owner.must(204, "DELETE", "/api/users/"+adaID+"/sessions", nil, nil)
	if n := e.asgardeo.SessionCount(adaAsgardeo); n != 0 {
		t.Fatalf("after ending all: %d", n)
	}

	owner.must(200, "POST", "/api/users/"+adaID+"/reset-password", nil, nil)
	if !e.asgardeo.User(adaAsgardeo).ResetRequested {
		t.Fatal("no reset requested in Asgardeo")
	}

	// Not the owner's account, and not one that is suspended.
	var ownerUser struct {
		Users []store.User `json:"users"`
	}
	owner.must(200, "GET", "/api/users?type=Owner", nil, &ownerUser)
	admin := e.appointAdmin(owner, "ben@zeit26.test")
	admin.must(409, "POST", "/api/users/"+ownerUser.Users[0].ID+"/reset-password", nil, nil)
	admin.must(409, "DELETE", "/api/users/"+ownerUser.Users[0].ID+"/sessions", nil, nil)
	owner.must(200, "POST", "/api/users/"+adaID+"/lock", nil, nil)
	owner.must(409, "POST", "/api/users/"+adaID+"/reset-password", nil, nil)
}

func TestPoliciesAreTheOwners(t *testing.T) {
	e := setup(t)
	e.asgardeo.ConsoleAuthorized = true
	owner, _, _ := e.signIn(e.ownerID)

	var list struct {
		Policies []asgardeo.Policy `json:"policies"`
	}
	owner.must(200, "GET", "/api/asgardeo/policies", nil, &list)
	var lock asgardeo.Policy
	for _, p := range list.Policies {
		if p.ID == "conn-lock" {
			lock = p
		}
	}
	if lock.Name != "Login Attempts" || len(lock.Properties) != 2 {
		t.Fatalf("policy read without its values: %+v", lock)
	}

	path := "/api/asgardeo/policies/" + lock.CategoryID + "/" + lock.ID
	var updated struct {
		Policy asgardeo.Policy `json:"policy"`
	}
	owner.must(200, "PATCH", path, map[string]any{"values": map[string]string{"account.lock.handler.On.Failure.Max.Attempts": "3"}}, &updated)
	if got := e.asgardeo.PolicyValue("conn-lock", "account.lock.handler.On.Failure.Max.Attempts"); got != "3" {
		t.Fatalf("in Asgardeo: %q", got)
	}
	owner.must(400, "PATCH", path, map[string]any{"values": map[string]string{"made.up": "1"}}, nil)

	admin := e.appointAdmin(owner, "ben@zeit26.test")
	admin.must(200, "GET", "/api/asgardeo/policies", nil, nil)
	admin.must(403, "PATCH", path, map[string]any{"values": map[string]string{"account.lock.handler.enable": "false"}}, nil)
}
