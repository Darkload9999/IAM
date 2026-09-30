package hub

// The Asgardeo console, through the Hub: groups, roles, registered
// applications, users' sessions, password resets and the organization's
// login and security policies. Every change is audited, and the Hub's own
// rules still hold - the organization owner's account is left alone, an
// application's access group is managed through access, and only the owner
// changes the organization's security policies.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeit26/identity-hub/internal/asgardeo"
	"github.com/zeit26/identity-hub/internal/store"
)

// Console is the part of Asgardeo beyond users the Hub offers.
type Console interface {
	Capabilities(ctx context.Context, fresh bool) ([]asgardeo.Capability, error)
	Can(ctx context.Context, module string) bool

	ListGroups(ctx context.Context) ([]asgardeo.Group, error)
	GetGroup(ctx context.Context, id string) (*asgardeo.Group, error)
	CreateGroup(ctx context.Context, displayName string) (string, error)
	RenameGroup(ctx context.Context, id, name string) error
	DeleteGroup(ctx context.Context, id string) error
	AddGroupMember(ctx context.Context, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error

	ListRoles(ctx context.Context) ([]asgardeo.Role, error)
	GetRole(ctx context.Context, id string) (*asgardeo.Role, error)
	CreateRole(ctx context.Context, name string) (string, error)
	DeleteRole(ctx context.Context, id string) error
	AssignRole(ctx context.Context, roleID, kind, memberID string) error
	UnassignRole(ctx context.Context, roleID, kind, memberID string) error

	ListApplications(ctx context.Context) ([]asgardeo.Application, error)
	GetApplication(ctx context.Context, id string) (*asgardeo.Application, error)

	ListSessions(ctx context.Context, userID string) ([]asgardeo.Session, error)
	TerminateSession(ctx context.Context, userID, sessionID string) error

	ForcePasswordReset(ctx context.Context, id string) error

	ListPolicies(ctx context.Context) ([]asgardeo.Policy, error)
	UpdatePolicy(ctx context.Context, categoryID, connectorID string, values map[string]string) error
}

func (s *Service) consoleFor(ctx context.Context, module string) (Console, error) {
	console, ok := s.dir.(Console)
	if !ok {
		return nil, refuse(501, "NOT_AVAILABLE", "This Hub cannot reach the Asgardeo console APIs")
	}
	if !console.Can(ctx, module) {
		for _, m := range asgardeo.Modules {
			if m.Key == module {
				return nil, refuse(403, "NOT_AUTHORIZED",
					"The Hub's M2M application is not authorized for the %s in Asgardeo (%s). Authorize it with %s, then try again.",
					m.API, m.Group, strings.Join(m.Scopes, ", "))
			}
		}
		return nil, refuse(403, "NOT_AUTHORIZED", "Not authorized in Asgardeo")
	}
	return console, nil
}

// Capabilities: which parts of Asgardeo the Hub may manage right now.
func (s *Service) Capabilities(ctx context.Context, fresh bool) ([]asgardeo.Capability, error) {
	console, ok := s.dir.(Console)
	if !ok {
		return []asgardeo.Capability{}, nil
	}
	caps, err := console.Capabilities(ctx, fresh)
	if err != nil {
		return nil, asgardeoRefusal(err, "report what the Hub may manage")
	}
	return caps, nil
}

// PersonRef is an Asgardeo member as the dashboard shows it: joined to the
// Hub's record of the person when there is one.
type PersonRef struct {
	AsgardeoID string `json:"asgardeoId"`
	UserID     string `json:"userId"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}

func (s *Service) people(ctx context.Context, refs []asgardeo.Ref) []PersonRef {
	out := make([]PersonRef, 0, len(refs))
	for _, r := range refs {
		p := PersonRef{AsgardeoID: r.ID, Name: r.Display, Email: r.Display}
		if u, err := store.GetUserByAsgardeoID(ctx, s.store.Pool, r.ID); err == nil {
			p.UserID = u.ID
			p.Email = u.Email
			if name := strings.TrimSpace(u.GivenName + " " + u.FamilyName); name != "" {
				p.Name = name
			}
		}
		out = append(out, p)
	}
	return out
}

// member resolves a Hub user id to the Asgardeo account it stands for.
func (s *Service) member(ctx context.Context, userID string) (store.User, error) {
	u, err := s.getUser(ctx, userID)
	if err != nil {
		return u, err
	}
	if u.RemovedAt != nil {
		return u, refuse(409, "REMOVED", "%s no longer exists in Asgardeo", u.Email)
	}
	return u, nil
}

// ---------------------------------------------------------------- groups

type GroupView struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Members []PersonRef `json:"members"`
	// The Hub application whose access group this is; its members are
	// managed through access, not here.
	AppID   string `json:"appId,omitempty"`
	AppName string `json:"appName,omitempty"`
}

func (s *Service) groupView(ctx context.Context, g asgardeo.Group, apps []store.Application) GroupView {
	v := GroupView{ID: g.ID, Name: g.Name, Members: s.people(ctx, g.Members)}
	for _, a := range apps {
		if a.AsgardeoGroupID == g.ID {
			v.AppID, v.AppName = a.ID, a.Name
		}
	}
	return v
}

func (s *Service) ListGroups(ctx context.Context) ([]GroupView, error) {
	console, err := s.consoleFor(ctx, "groups")
	if err != nil {
		return nil, err
	}
	groups, err := console.ListGroups(ctx)
	if err != nil {
		return nil, asgardeoRefusal(err, "list the groups")
	}
	apps, err := store.ListApps(ctx, s.store.Pool)
	if err != nil {
		return nil, err
	}
	out := make([]GroupView, 0, len(groups))
	for _, g := range groups {
		out = append(out, s.groupView(ctx, g, apps))
	}
	return out, nil
}

func (s *Service) GetGroup(ctx context.Context, id string) (GroupView, error) {
	console, err := s.consoleFor(ctx, "groups")
	if err != nil {
		return GroupView{}, err
	}
	g, err := console.GetGroup(ctx, id)
	if err != nil {
		return GroupView{}, asgardeoRefusal(err, "read the group")
	}
	if g == nil {
		return GroupView{}, refuse(404, "NOT_FOUND", "Group not found")
	}
	apps, err := store.ListApps(ctx, s.store.Pool)
	if err != nil {
		return GroupView{}, err
	}
	return s.groupView(ctx, *g, apps), nil
}

func (s *Service) CreateConsoleGroup(ctx context.Context, actor, name string) (GroupView, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return GroupView{}, refuse(400, "VALIDATION", "A group name of up to 100 characters is required")
	}
	console, err := s.consoleFor(ctx, "groups")
	if err != nil {
		return GroupView{}, err
	}
	id, err := console.CreateGroup(ctx, name)
	if err != nil {
		return GroupView{}, asgardeoRefusal(err, "create the group")
	}
	_ = store.Audit(ctx, s.store.Pool, actor, "group.create", "group", id, "Created Asgardeo group "+name, nil)
	return s.GetGroup(ctx, id)
}

func (s *Service) RenameConsoleGroup(ctx context.Context, actor, id, name string) (GroupView, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return GroupView{}, refuse(400, "VALIDATION", "A group name of up to 100 characters is required")
	}
	group, err := s.editableGroup(ctx, id, "renamed")
	if err != nil {
		return group, err
	}
	console, _ := s.consoleFor(ctx, "groups")
	if err := console.RenameGroup(ctx, id, name); err != nil {
		return group, asgardeoRefusal(err, "rename the group")
	}
	_ = store.Audit(ctx, s.store.Pool, actor, "group.rename", "group", id,
		fmt.Sprintf("Renamed Asgardeo group %s to %s", group.Name, name), nil)
	return s.GetGroup(ctx, id)
}

func (s *Service) DeleteConsoleGroup(ctx context.Context, actor, id string) error {
	group, err := s.editableGroup(ctx, id, "deleted")
	if err != nil {
		return err
	}
	console, _ := s.consoleFor(ctx, "groups")
	if err := console.DeleteGroup(ctx, id); err != nil {
		return asgardeoRefusal(err, "delete the group")
	}
	return store.Audit(ctx, s.store.Pool, actor, "group.delete", "group", id, "Deleted Asgardeo group "+group.Name, nil)
}

// SetGroupMember puts a person in a group, or takes them out.
func (s *Service) SetGroupMember(ctx context.Context, actor, groupID, userID string, member bool) (GroupView, error) {
	group, err := s.editableGroup(ctx, groupID, "changed")
	if err != nil {
		return group, err
	}
	u, err := s.member(ctx, userID)
	if err != nil {
		return group, err
	}
	console, _ := s.consoleFor(ctx, "groups")
	action, summary := "group.member.add", fmt.Sprintf("Added %s to group %s", u.Email, group.Name)
	if member {
		err = console.AddGroupMember(ctx, groupID, u.AsgardeoID)
	} else {
		action, summary = "group.member.remove", fmt.Sprintf("Removed %s from group %s", u.Email, group.Name)
		err = console.RemoveGroupMember(ctx, groupID, u.AsgardeoID)
	}
	if err != nil {
		return group, asgardeoRefusal(err, "change the group's members")
	}
	_ = store.Audit(ctx, s.store.Pool, actor, action, "group", groupID, summary, map[string]any{"userId": userID})
	return s.GetGroup(ctx, groupID)
}

// editableGroup refuses the access groups of the Hub's applications: their
// members follow access given in the Hub, which would otherwise disagree.
func (s *Service) editableGroup(ctx context.Context, id, what string) (GroupView, error) {
	group, err := s.GetGroup(ctx, id)
	if err != nil {
		return group, err
	}
	if group.AppID != "" {
		return group, refuse(409, "APP_GROUP",
			"This is the access group of %s: its members are managed by giving or removing access to %s, and it cannot be %s here.",
			group.AppName, group.AppName, what)
	}
	return group, nil
}

// ----------------------------------------------------------------- roles

type RoleView struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Audience    string         `json:"audience"`
	AudienceOf  string         `json:"audienceOf"`
	Permissions []asgardeo.Ref `json:"permissions"`
	Users       []PersonRef    `json:"users"`
	Groups      []asgardeo.Ref `json:"groups"`
	// Asgardeo's own administrative roles are not changed from the Hub.
	System bool `json:"system"`
}

// systemRoles are Asgardeo's built-in organization roles.
var systemRoles = map[string]bool{"administrator": true, "everyone": true, "selfsignup": true}

func (s *Service) roleView(ctx context.Context, r asgardeo.Role) RoleView {
	groups := r.Groups
	if groups == nil {
		groups = []asgardeo.Ref{}
	}
	return RoleView{ID: r.ID, Name: r.Name, Audience: r.Audience, AudienceOf: r.AudienceOf,
		Permissions: r.Permissions, Users: s.people(ctx, r.Users), Groups: groups,
		System: systemRoles[strings.ToLower(r.Name)] && r.Audience == "organization"}
}

func (s *Service) ListConsoleRoles(ctx context.Context) ([]RoleView, error) {
	console, err := s.consoleFor(ctx, "roles")
	if err != nil {
		return nil, err
	}
	roles, err := console.ListRoles(ctx)
	if err != nil {
		return nil, asgardeoRefusal(err, "list the roles")
	}
	out := make([]RoleView, 0, len(roles))
	for _, r := range roles {
		out = append(out, s.roleView(ctx, r))
	}
	return out, nil
}

func (s *Service) GetConsoleRole(ctx context.Context, id string) (RoleView, error) {
	console, err := s.consoleFor(ctx, "roles")
	if err != nil {
		return RoleView{}, err
	}
	r, err := console.GetRole(ctx, id)
	if err != nil {
		return RoleView{}, asgardeoRefusal(err, "read the role")
	}
	if r == nil {
		return RoleView{}, refuse(404, "NOT_FOUND", "Role not found")
	}
	return s.roleView(ctx, *r), nil
}

func (s *Service) CreateConsoleRole(ctx context.Context, actor, name string) (RoleView, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return RoleView{}, refuse(400, "VALIDATION", "A role name of up to 100 characters is required")
	}
	console, err := s.consoleFor(ctx, "roles")
	if err != nil {
		return RoleView{}, err
	}
	id, err := console.CreateRole(ctx, name)
	if err != nil {
		return RoleView{}, asgardeoRefusal(err, "create the role")
	}
	_ = store.Audit(ctx, s.store.Pool, actor, "role.asgardeo.create", "asgardeo-role", id, "Created Asgardeo role "+name, nil)
	return s.GetConsoleRole(ctx, id)
}

func (s *Service) DeleteConsoleRole(ctx context.Context, actor, id string) error {
	role, err := s.GetConsoleRole(ctx, id)
	if err != nil {
		return err
	}
	if role.System {
		return refuse(409, "PROTECTED", "%s is one of Asgardeo's own roles and cannot be deleted", role.Name)
	}
	console, _ := s.consoleFor(ctx, "roles")
	if err := console.DeleteRole(ctx, id); err != nil {
		return asgardeoRefusal(err, "delete the role")
	}
	return store.Audit(ctx, s.store.Pool, actor, "role.asgardeo.delete", "asgardeo-role", id, "Deleted Asgardeo role "+role.Name, nil)
}

// SetRoleMember gives a role to a person (kind "users", memberID a Hub user
// id) or to a group (kind "groups", memberID the Asgardeo group id), or
// takes it away.
func (s *Service) SetRoleMember(ctx context.Context, actor, roleID, kind, memberID string, assigned bool) (RoleView, error) {
	role, err := s.GetConsoleRole(ctx, roleID)
	if err != nil {
		return role, err
	}
	if role.System && strings.EqualFold(role.Name, "everyone") {
		return role, refuse(409, "PROTECTED", "Everybody holds the everyone role; it is not assigned")
	}

	target, label := memberID, memberID
	switch kind {
	case "users":
		u, err := s.member(ctx, memberID)
		if err != nil {
			return role, err
		}
		if owner, err := s.IsOwnerAccount(ctx, u); err != nil {
			return role, err
		} else if owner && !assigned {
			return role, refuse(409, "PROTECTED", "The organization owner's roles are managed in the Asgardeo console")
		}
		target, label = u.AsgardeoID, u.Email
	case "groups":
		console, err := s.consoleFor(ctx, "groups")
		if err == nil {
			if g, err := console.GetGroup(ctx, memberID); err == nil && g != nil {
				label = "group " + g.Name
			}
		}
	default:
		return role, refuse(400, "VALIDATION", "Roles are given to users or groups")
	}

	console, _ := s.consoleFor(ctx, "roles")
	action, summary := "role.asgardeo.assign", fmt.Sprintf("Gave Asgardeo role %s to %s", role.Name, label)
	if assigned {
		err = console.AssignRole(ctx, roleID, kind, target)
	} else {
		action, summary = "role.asgardeo.unassign", fmt.Sprintf("Took Asgardeo role %s from %s", role.Name, label)
		err = console.UnassignRole(ctx, roleID, kind, target)
	}
	if err != nil {
		return role, asgardeoRefusal(err, "change the role's assignments")
	}
	_ = store.Audit(ctx, s.store.Pool, actor, action, "asgardeo-role", roleID, summary, map[string]any{"kind": kind, "member": memberID})
	return s.GetConsoleRole(ctx, roleID)
}

// ---------------------------------------------------------- applications

// ConsoleApp is an application registered in Asgardeo, and whether the Hub
// already manages access to it.
type ConsoleApp struct {
	asgardeo.Application
	HubAppID string `json:"hubAppId,omitempty"`
}

func (s *Service) ListConsoleApps(ctx context.Context) ([]ConsoleApp, error) {
	console, err := s.consoleFor(ctx, "applications")
	if err != nil {
		return nil, err
	}
	apps, err := console.ListApplications(ctx)
	if err != nil {
		return nil, asgardeoRefusal(err, "list the applications")
	}
	hubApps, err := store.ListApps(ctx, s.store.Pool)
	if err != nil {
		return nil, err
	}
	out := make([]ConsoleApp, 0, len(apps))
	for _, a := range apps {
		out = append(out, ConsoleApp{Application: a, HubAppID: matchHubApp(a, hubApps)})
	}
	return out, nil
}

func (s *Service) GetConsoleApp(ctx context.Context, id string) (ConsoleApp, error) {
	console, err := s.consoleFor(ctx, "applications")
	if err != nil {
		return ConsoleApp{}, err
	}
	a, err := console.GetApplication(ctx, id)
	if err != nil {
		return ConsoleApp{}, asgardeoRefusal(err, "read the application")
	}
	if a == nil {
		return ConsoleApp{}, refuse(404, "NOT_FOUND", "Application not found")
	}
	hubApps, err := store.ListApps(ctx, s.store.Pool)
	if err != nil {
		return ConsoleApp{}, err
	}
	return ConsoleApp{Application: *a, HubAppID: matchHubApp(*a, hubApps)}, nil
}

// matchHubApp: the Hub application for this Asgardeo one, by its address.
func matchHubApp(a asgardeo.Application, hubApps []store.Application) string {
	for _, h := range hubApps {
		if h.URL != "" && a.AccessURL != "" && strings.TrimRight(h.URL, "/") == strings.TrimRight(a.AccessURL, "/") {
			return h.ID
		}
		if strings.EqualFold(h.Name, a.Name) {
			return h.ID
		}
	}
	return ""
}

// -------------------------------------------------------------- sessions

func (s *Service) ListSessions(ctx context.Context, userID string) ([]asgardeo.Session, error) {
	u, err := s.member(ctx, userID)
	if err != nil {
		return nil, err
	}
	console, err := s.consoleFor(ctx, "sessions")
	if err != nil {
		return nil, err
	}
	sessions, err := console.ListSessions(ctx, u.AsgardeoID)
	if err != nil {
		return nil, asgardeoRefusal(err, "list the sessions")
	}
	return sessions, nil
}

// TerminateSessions signs the person out: of one session, or of all of them
// when sessionID is "".
func (s *Service) TerminateSessions(ctx context.Context, actor, userID, sessionID string) error {
	u, err := s.member(ctx, userID)
	if err != nil {
		return err
	}
	if owner, err := s.IsOwnerAccount(ctx, u); err != nil {
		return err
	} else if owner && !strings.EqualFold(actor, u.Email) {
		return refuse(409, "PROTECTED", "Only the organization owner can end the owner's sessions")
	}
	console, err := s.consoleFor(ctx, "sessions")
	if err != nil {
		return err
	}
	if err := console.TerminateSession(ctx, u.AsgardeoID, sessionID); err != nil {
		return asgardeoRefusal(err, "end the session")
	}
	summary := "Signed " + u.Email + " out of every session"
	if sessionID != "" {
		summary = "Ended a session of " + u.Email
	}
	return store.Audit(ctx, s.store.Pool, actor, "user.sessions.end", "user", userID, summary, map[string]any{"session": sessionID})
}

// ResetPassword has Asgardeo email the person a link to choose a new
// password; the one they have stops working.
func (s *Service) ResetPassword(ctx context.Context, actor, userID string) error {
	u, err := s.member(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.protect(ctx, u, "reset"); err != nil {
		return err
	}
	if u.Locked {
		return refuse(409, "LOCKED", "%s is suspended. Restore the account first.", u.Email)
	}
	console, err := s.consoleFor(ctx, "users")
	if err != nil {
		return err
	}
	if err := console.ForcePasswordReset(ctx, u.AsgardeoID); err != nil {
		var ae *asgardeo.Error
		if errors.As(err, &ae) && (ae.Status == 400 || ae.Status == 403) {
			return refuse(409, "RESET_DISABLED",
				"Asgardeo refused the reset (%s). Turn on Admin Initiated Password Reset (by email link) in Asgardeo: Login & Registration > Account Recovery.", ae.Detail)
		}
		return asgardeoRefusal(err, "start the password reset")
	}
	return store.Audit(ctx, s.store.Pool, actor, "user.password.reset", "user", userID, "Sent "+u.Email+" a password reset link", nil)
}

// -------------------------------------------------------------- policies

func (s *Service) ListPolicies(ctx context.Context) ([]asgardeo.Policy, error) {
	console, err := s.consoleFor(ctx, "security")
	if err != nil {
		return nil, err
	}
	policies, err := console.ListPolicies(ctx)
	if err != nil {
		return nil, asgardeoRefusal(err, "read the login and security policies")
	}
	return policies, nil
}

// UpdatePolicy changes some properties of one policy. Only properties the
// policy already has are accepted, and only as text Asgardeo understands.
func (s *Service) UpdatePolicy(ctx context.Context, actor, categoryID, policyID string, values map[string]string) (asgardeo.Policy, error) {
	console, err := s.consoleFor(ctx, "security")
	if err != nil {
		return asgardeo.Policy{}, err
	}
	policies, err := console.ListPolicies(ctx)
	if err != nil {
		return asgardeo.Policy{}, asgardeoRefusal(err, "read the login and security policies")
	}
	var current *asgardeo.Policy
	for i := range policies {
		if policies[i].CategoryID == categoryID && policies[i].ID == policyID {
			current = &policies[i]
		}
	}
	if current == nil {
		return asgardeo.Policy{}, refuse(404, "NOT_FOUND", "Policy not found")
	}
	if len(values) == 0 {
		return *current, refuse(400, "VALIDATION", "Nothing to change")
	}
	known := map[string]string{}
	for _, p := range current.Properties {
		known[p.Name] = p.Value
	}
	changed := map[string]any{}
	for name, value := range values {
		before, ok := known[name]
		if !ok {
			return *current, refuse(400, "VALIDATION", "%s is not a setting of %s", name, current.Name)
		}
		if len(value) > 2000 {
			return *current, refuse(400, "VALIDATION", "The value of %s is too long", name)
		}
		changed[name] = map[string]string{"from": before, "to": value}
	}
	if err := console.UpdatePolicy(ctx, categoryID, policyID, values); err != nil {
		return *current, asgardeoRefusal(err, "change the policy")
	}
	_ = store.Audit(ctx, s.store.Pool, actor, "policy.update", "policy", policyID, "Changed "+current.Name, changed)

	policies, err = console.ListPolicies(ctx)
	if err != nil {
		return *current, nil
	}
	for _, p := range policies {
		if p.CategoryID == categoryID && p.ID == policyID {
			return p, nil
		}
	}
	return *current, nil
}
