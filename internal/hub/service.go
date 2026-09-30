// Package hub is what the dashboard does: onboarding and offboarding people,
// giving them access to applications with roles and permissions, and
// keeping Asgardeo, the Hub and every application in step.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zeit26/identity-hub/internal/asgardeo"
	"github.com/zeit26/identity-hub/internal/provisioning"
	"github.com/zeit26/identity-hub/internal/secrets"
	"github.com/zeit26/identity-hub/internal/store"
)

// Error is a refusal meant for the admin: Status is the HTTP status to
// answer with, Message says what to do about it.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func refuse(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Directory is the part of Asgardeo the Hub uses (an interface, so tests
// can stand in for it).
type Directory interface {
	ListUsers(ctx context.Context) ([]asgardeo.User, error)
	GetUser(ctx context.Context, id string) (*asgardeo.User, error)
	CreateUser(ctx context.Context, givenName, familyName, email string) (*asgardeo.User, bool, error)
	UpdateName(ctx context.Context, id, givenName, familyName string) error
	SetLocked(ctx context.Context, id string, locked bool) error
	DeleteUser(ctx context.Context, id string) error
	CanManageGroups(ctx context.Context) bool
	CreateGroup(ctx context.Context, displayName string) (string, error)
	AddGroupMember(ctx context.Context, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
}

type Service struct {
	store *store.Store
	dir   Directory
	box   *secrets.Box
	log   *slog.Logger
	// Called after provisioning work is queued, to start it at once.
	wake func()

	syncMu sync.Mutex
}

func New(s *store.Store, dir Directory, box *secrets.Box, log *slog.Logger, wake func()) *Service {
	if wake == nil {
		wake = func() {}
	}
	return &Service{store: s, dir: dir, box: box, log: log, wake: wake}
}

// ---------------------------------------------------------------- admins

// Role of a signed-in person in the Hub.
type AdminRole string

const (
	RoleNone  AdminRole = ""
	RoleOwner AdminRole = "owner" // the organization owner: every power
	RoleAdmin AdminRole = "admin" // appointed by the owner
)

// Identify finds the account an admin signed in with, by the subject of
// their ID token. An account not synced yet is read from Asgardeo first.
func (s *Service) Identify(ctx context.Context, subject string) (store.User, error) {
	if strings.TrimSpace(subject) == "" {
		return store.User{}, store.ErrNotFound
	}
	user, err := store.GetUserBySubject(ctx, s.store.Pool, subject)
	if errors.Is(err, store.ErrNotFound) {
		if syncErr := s.SyncUsers(ctx); syncErr != nil {
			return user, syncErr
		}
		user, err = store.GetUserBySubject(ctx, s.store.Pool, subject)
	}
	return user, err
}

// AdminRoleOf decides who may use the dashboard: the organization owner
// always; anybody else only when the owner made their account a Hub admin.
// A locked or removed account has no role.
func (s *Service) AdminRoleOf(ctx context.Context, user store.User) (AdminRole, error) {
	if user.ID == "" || user.Locked || user.RemovedAt != nil {
		return RoleNone, nil
	}
	owner, err := s.IsOwnerAccount(ctx, user)
	if err != nil {
		return RoleNone, err
	}
	if owner {
		return RoleOwner, nil
	}
	ok, err := store.IsHubAdmin(ctx, s.store.Pool, user.ID)
	if err != nil || !ok {
		return RoleNone, err
	}
	return RoleAdmin, nil
}

// IsOwnerAccount: the organization owner's own account, or the account the
// owner signs in to applications with. Asgardeo keeps the owner outside the
// organization's user store, and applications only sign in accounts of that
// store; so the owner has a second account there, whose username is the
// owner's with the store prefix. Usernames cannot be changed, so - unlike an
// email address - nobody else can take this one on.
func (s *Service) IsOwnerAccount(ctx context.Context, user store.User) (bool, error) {
	if user.AccountType == "Owner" {
		return true, nil
	}
	ownerUsername, err := store.OwnerUsername(ctx, s.store.Pool)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(user.Username, asgardeo.UserStore+"/"+ownerUsername), nil
}

// protect refuses to change the organization owner's accounts from the Hub.
func (s *Service) protect(ctx context.Context, user store.User, what string) error {
	owner, err := s.IsOwnerAccount(ctx, user)
	if err != nil {
		return err
	}
	if owner {
		return refuse(409, "PROTECTED", "The organization owner's account cannot be %s from the Hub", what)
	}
	if user.AccountType != "Customer" {
		return refuse(409, "PROTECTED", "Console administrators are managed in the Asgardeo console")
	}
	return nil
}

// AddAdmin makes the account with this address a Hub admin.
func (s *Service) AddAdmin(ctx context.Context, actor, email string) (store.User, error) {
	email, err := normalEmail(email)
	if err != nil {
		return store.User{}, err
	}
	user, err := store.GetActiveUserByEmail(ctx, s.store.Pool, email)
	if errors.Is(err, store.ErrNotFound) {
		return user, refuse(404, "NOT_FOUND", "No single Asgardeo account has the address %s. Onboard the person first, or sync with Asgardeo.", email)
	} else if err != nil {
		return user, err
	}
	if owner, err := s.IsOwnerAccount(ctx, user); err != nil {
		return user, err
	} else if owner {
		return user, refuse(409, "PROTECTED", "The organization owner is always a Hub admin")
	}
	if user.Locked {
		return user, refuse(409, "LOCKED", "%s is suspended", email)
	}
	return user, s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.AddHubAdmin(ctx, tx, user.ID, email, actor); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "admin.add", "user", user.ID, "Made "+email+" a Hub admin", nil)
	})
}

// RemoveAdmin withdraws an appointment; the account itself is untouched.
func (s *Service) RemoveAdmin(ctx context.Context, actor, userID string) error {
	user, err := s.getUser(ctx, userID)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.RemoveHubAdmin(ctx, tx, userID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "%s is not a Hub admin", user.Email)
		} else if err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "admin.remove", "user", userID, "Removed "+user.Email+" as a Hub admin", nil)
	})
}

// RetryJob puts a failed provisioning job back in the queue.
func (s *Service) RetryJob(ctx context.Context, actor, jobID string) error {
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.RetryJob(ctx, tx, jobID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "No failed job with that id")
		} else if err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "job.retry", "job", jobID, "Retried a provisioning job", nil)
	})
	if err == nil {
		s.wake()
	}
	return err
}

// ----------------------------------------------------------------- users

type AccessInput struct {
	AppID         string   `json:"appId"`
	RoleIDs       []string `json:"roleIds"`
	PermissionIDs []string `json:"permissionIds"`
}

type NewUser struct {
	GivenName  string        `json:"givenName"`
	FamilyName string        `json:"familyName"`
	Email      string        `json:"email"`
	Department string        `json:"department"`
	Access     []AccessInput `json:"access"`
}

// Invitation: SENT - Asgardeo emailed a link to set a password;
// EXISTING_ACCOUNT - Asgardeo already had the person, nothing was sent.
type CreatedUser struct {
	User       store.User `json:"user"`
	Invitation string     `json:"invitation"`
}

// CreateUser onboards a person: created in Asgardeo (which invites them to
// set a password), recorded here, and given the access asked for.
func (s *Service) CreateUser(ctx context.Context, actor string, in NewUser) (*CreatedUser, error) {
	email, err := normalEmail(in.Email)
	if err != nil {
		return nil, err
	}
	in.GivenName = strings.TrimSpace(in.GivenName)
	in.FamilyName = strings.TrimSpace(in.FamilyName)
	if in.GivenName == "" {
		return nil, refuse(400, "VALIDATION", "A first name is required")
	}
	for _, access := range in.Access {
		if _, err := store.GetApp(ctx, s.store.Pool, access.AppID); err != nil {
			return nil, refuse(400, "VALIDATION", "An application chosen for access does not exist")
		}
	}

	remote, created, err := s.dir.CreateUser(ctx, in.GivenName, in.FamilyName, email)
	if err != nil {
		return nil, asgardeoRefusal(err, "create the account")
	}

	user, err := store.UpsertUser(ctx, s.store.Pool, fromDirectory(*remote, strings.TrimSpace(in.Department), true))
	if err != nil {
		return nil, err
	}
	invitation := "EXISTING_ACCOUNT"
	if created {
		invitation = "SENT"
	}
	if err := store.Audit(ctx, s.store.Pool, actor, "user.create", "user", user.ID,
		fmt.Sprintf("Created %s (%s)", email, invitation),
		map[string]any{"invitation": invitation, "asgardeoId": remote.ID}); err != nil {
		return nil, err
	}

	for _, access := range in.Access {
		if err := s.SetAccess(ctx, actor, user.ID, access); err != nil {
			return &CreatedUser{User: user, Invitation: invitation}, fmt.Errorf("the account was created, but access could not be given: %w", err)
		}
	}
	return &CreatedUser{User: user, Invitation: invitation}, nil
}

type UserUpdate struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	Department string `json:"department"`
}

// UpdateUser changes the name (in Asgardeo too) and department, and pushes
// the change to every application the person has.
func (s *Service) UpdateUser(ctx context.Context, actor, userID string, in UserUpdate) (store.User, error) {
	user, err := s.getUser(ctx, userID)
	if err != nil {
		return user, err
	}
	in.GivenName = strings.TrimSpace(in.GivenName)
	in.FamilyName = strings.TrimSpace(in.FamilyName)
	if in.GivenName == "" {
		return user, refuse(400, "VALIDATION", "A first name is required")
	}
	if user.AccountType != "Customer" {
		return user, refuse(409, "PROTECTED", "The organization owner and console administrators are managed in the Asgardeo console")
	}

	if in.GivenName != user.GivenName || in.FamilyName != user.FamilyName {
		if err := s.dir.UpdateName(ctx, user.AsgardeoID, in.GivenName, in.FamilyName); err != nil {
			return user, asgardeoRefusal(err, "update the name")
		}
	}
	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.UpdateUserProfile(ctx, tx, userID, in.GivenName, in.FamilyName, strings.TrimSpace(in.Department)); err != nil {
			return err
		}
		if err := s.pushToAllApps(ctx, tx, userID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "user.update", "user", userID, "Updated "+user.Email, map[string]any{
			"givenName": in.GivenName, "familyName": in.FamilyName, "department": in.Department})
	})
	if err != nil {
		return user, err
	}
	s.wake()
	return store.GetUser(ctx, s.store.Pool, userID)
}

// SetLocked suspends or restores a person: locked in Asgardeo (no sign-in
// anywhere) and marked inactive in every application.
func (s *Service) SetLocked(ctx context.Context, actor, userID string, locked bool) (store.User, error) {
	user, err := s.getUser(ctx, userID)
	if err != nil {
		return user, err
	}
	if err := s.protect(ctx, user, "suspended"); err != nil {
		return user, err
	}
	if err := s.dir.SetLocked(ctx, user.AsgardeoID, locked); err != nil {
		return user, asgardeoRefusal(err, "change the account's lock")
	}
	action, summary := "user.unlock", "Restored "+user.Email
	if locked {
		action, summary = "user.lock", "Suspended "+user.Email
	}
	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.SetUserLocked(ctx, tx, userID, locked); err != nil {
			return err
		}
		if err := s.pushToAllApps(ctx, tx, userID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, action, "user", userID, summary, nil)
	})
	if err != nil {
		return user, err
	}
	s.wake()
	return store.GetUser(ctx, s.store.Pool, userID)
}

// DeleteUser offboards a person: deactivated in every application, removed
// from every access group, and deleted from Asgardeo. Their record here is
// kept, marked removed, for the audit trail.
func (s *Service) DeleteUser(ctx context.Context, actor, userID string) error {
	user, err := s.getUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.protect(ctx, user, "deleted"); err != nil {
		return err
	}
	if strings.EqualFold(user.Email, actor) {
		return refuse(409, "PROTECTED", "You cannot delete your own account")
	}

	grants, err := store.ListGrantsForUser(ctx, s.store.Pool, userID)
	if err != nil {
		return err
	}
	for _, g := range grants {
		s.leaveGroup(ctx, g.AppID, user.AsgardeoID)
	}
	if err := s.dir.DeleteUser(ctx, user.AsgardeoID); err != nil {
		return asgardeoRefusal(err, "delete the account")
	}

	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET removed_at = now(), locked = true, updated_at = now() WHERE id = $1`, userID); err != nil {
			return err
		}
		for _, g := range grants {
			if err := store.SetGrantStatus(ctx, tx, userID, g.AppID, "revoking", ""); err != nil {
				return err
			}
			if err := store.EnqueueJob(ctx, tx, userID, g.AppID, "deprovision"); err != nil {
				return err
			}
		}
		return store.Audit(ctx, tx, actor, "user.delete", "user", userID, "Deleted "+user.Email, map[string]any{
			"applications": len(grants)})
	})
	if err == nil {
		s.wake()
	}
	return err
}

// ---------------------------------------------------------------- access

// SetAccess gives the person access to the application with exactly these
// roles and extra permissions (replacing what they had there), adds them
// to its Asgardeo access group, and pushes it to the application.
func (s *Service) SetAccess(ctx context.Context, actor, userID string, in AccessInput) error {
	user, err := s.getUser(ctx, userID)
	if err != nil {
		return err
	}
	if user.RemovedAt != nil {
		return refuse(409, "REMOVED", "This account no longer exists in Asgardeo")
	}
	app, err := store.GetApp(ctx, s.store.Pool, in.AppID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "NOT_FOUND", "Application not found")
	} else if err != nil {
		return err
	}
	if app.AsgardeoGroupID != "" {
		if err := s.dir.AddGroupMember(ctx, app.AsgardeoGroupID, user.AsgardeoID); err != nil {
			return asgardeoRefusal(err, "add the person to the application's Asgardeo group")
		}
	}

	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := store.UpsertGrant(ctx, tx, userID, app.ID, actor, in.RoleIDs, in.PermissionIDs); err != nil {
			return err
		}
		if err := store.EnqueueJob(ctx, tx, userID, app.ID, "upsert"); err != nil {
			return err
		}
		grant, err := store.GetGrant(ctx, tx, userID, app.ID)
		if err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "access.set", "user", userID,
			fmt.Sprintf("Gave %s access to %s", user.Email, app.Name),
			map[string]any{"app": app.Key, "roles": grant.RoleIDs, "permissions": grant.EffectivePermissions})
	})
	if err == nil {
		s.wake()
	}
	return err
}

// RevokeAccess takes the application away: out of its Asgardeo group, and
// deactivated there.
func (s *Service) RevokeAccess(ctx context.Context, actor, userID, appID string) error {
	user, err := s.getUser(ctx, userID)
	if err != nil {
		return err
	}
	grant, err := store.GetGrant(ctx, s.store.Pool, userID, appID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "NOT_FOUND", "This person has no access to that application")
	} else if err != nil {
		return err
	}
	s.leaveGroup(ctx, appID, user.AsgardeoID)

	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.SetGrantStatus(ctx, tx, userID, appID, "revoking", ""); err != nil {
			return err
		}
		if err := store.EnqueueJob(ctx, tx, userID, appID, "deprovision"); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "access.revoke", "user", userID,
			fmt.Sprintf("Removed %s from %s", user.Email, grant.AppName), map[string]any{"app": grant.AppKey})
	})
	if err == nil {
		s.wake()
	}
	return err
}

func (s *Service) leaveGroup(ctx context.Context, appID, asgardeoID string) {
	app, err := store.GetApp(ctx, s.store.Pool, appID)
	if err != nil || app.AsgardeoGroupID == "" {
		return
	}
	if err := s.dir.RemoveGroupMember(ctx, app.AsgardeoGroupID, asgardeoID); err != nil {
		s.log.Warn("removing from Asgardeo group", "app", app.Key, "error", err)
	}
}

// pushToAllApps queues an update of the person in every application.
func (s *Service) pushToAllApps(ctx context.Context, q store.Q, userID string) error {
	grants, err := store.ListGrantsForUser(ctx, q, userID)
	if err != nil {
		return err
	}
	for _, g := range grants {
		if g.SyncStatus == "revoking" {
			continue
		}
		if err := store.EnqueueJob(ctx, q, userID, g.AppID, "upsert"); err != nil {
			return err
		}
	}
	return nil
}

// pushAppUsers queues an update of everybody with access to the
// application - after its roles or permissions changed.
func (s *Service) pushAppUsers(ctx context.Context, q store.Q, appID string) error {
	users, err := store.UsersOfApp(ctx, q, appID)
	if err != nil {
		return err
	}
	for _, userID := range users {
		if err := store.EnqueueJob(ctx, q, userID, appID, "upsert"); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------- applications

type AppInput struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	SCIMURL     string `json:"scimUrl"`
	// A token the application issued for the Hub. Empty on registration:
	// the Hub makes one up and shows it once. Empty on an update: kept.
	SCIMToken string `json:"scimToken"`
}

var appKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

func (in *AppInput) clean() error {
	in.Key = strings.ToLower(strings.TrimSpace(in.Key))
	in.Name = strings.TrimSpace(in.Name)
	in.URL = strings.TrimSpace(in.URL)
	in.SCIMURL = strings.TrimRight(strings.TrimSpace(in.SCIMURL), "/")
	in.SCIMToken = strings.TrimSpace(in.SCIMToken)
	if in.SCIMToken != "" && len(in.SCIMToken) < 24 {
		return refuse(400, "VALIDATION", "The application's token is too short to be a real one (under 24 characters)")
	}
	if in.Name == "" {
		return refuse(400, "VALIDATION", "A name is required")
	}
	for label, value := range map[string]string{"Application URL": in.URL, "SCIM endpoint": in.SCIMURL} {
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return refuse(400, "VALIDATION", "%s must be an absolute http(s) URL", label)
		}
	}
	return nil
}

// CreateApp registers an application. When it takes pushes, a token for
// its SCIM endpoint is generated and returned - once, never again.
func (s *Service) CreateApp(ctx context.Context, actor string, in AppInput) (store.Application, string, error) {
	if err := in.clean(); err != nil {
		return store.Application{}, "", err
	}
	if !appKeyPattern.MatchString(in.Key) {
		return store.Application{}, "", refuse(400, "VALIDATION", "The key must be 2-40 lowercase letters, digits or dashes, starting with a letter")
	}
	// Shown once: a token the Hub made up. One the application issued is
	// already known to whoever typed it in.
	token, sealed := "", ""
	if in.SCIMURL != "" {
		given := in.SCIMToken
		if given == "" {
			token = secrets.RandomToken()
			given = token
		}
		var err error
		if sealed, err = s.box.Seal(given); err != nil {
			return store.Application{}, "", err
		}
	}

	var app store.Application
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		app, err = store.CreateApp(ctx, tx, store.Application{Key: in.Key, Name: in.Name, Description: in.Description,
			URL: in.URL, SCIMURL: in.SCIMURL, SCIMTokenEncrypted: sealed})
		if store.IsUniqueViolation(err) {
			return refuse(409, "DUPLICATE", "An application with the key %q already exists", in.Key)
		}
		if err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "app.create", "application", app.ID, "Registered "+app.Name, map[string]any{"key": app.Key})
	})
	return app, token, err
}

func (s *Service) UpdateApp(ctx context.Context, actor, appID string, in AppInput) (store.Application, error) {
	if err := in.clean(); err != nil {
		return store.Application{}, err
	}
	var newToken *string
	if in.SCIMToken != "" {
		sealed, err := s.box.Seal(in.SCIMToken)
		if err != nil {
			return store.Application{}, err
		}
		newToken = &sealed
	}
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		current, err := store.GetApp(ctx, tx, appID)
		if errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Application not found")
		} else if err != nil {
			return err
		}
		if err := store.UpdateApp(ctx, tx, store.Application{ID: appID, Name: in.Name, Description: in.Description,
			URL: in.URL, SCIMURL: in.SCIMURL}, newToken); err != nil {
			return err
		}
		if current.SCIMURL != in.SCIMURL || newToken != nil {
			// A new endpoint: everybody is pushed to it.
			if err := s.pushAppUsers(ctx, tx, appID); err != nil {
				return err
			}
		}
		return store.Audit(ctx, tx, actor, "app.update", "application", appID, "Updated "+in.Name, nil)
	})
	if err != nil {
		return store.Application{}, err
	}
	s.wake()
	return store.GetApp(ctx, s.store.Pool, appID)
}

// RotateSCIMToken issues a new token for the application's SCIM endpoint;
// the old one stops being sent at once. Returned once, never again.
func (s *Service) RotateSCIMToken(ctx context.Context, actor, appID string) (string, error) {
	token := secrets.RandomToken()
	sealed, err := s.box.Seal(token)
	if err != nil {
		return "", err
	}
	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		app, err := store.GetApp(ctx, tx, appID)
		if errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Application not found")
		} else if err != nil {
			return err
		}
		if err := store.UpdateApp(ctx, tx, app, &sealed); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "app.token", "application", appID, "Issued a new SCIM token for "+app.Name, nil)
	})
	return token, err
}

// connection is the application's provisioning endpoint and its token.
func (s *Service) connection(ctx context.Context, appID string) (store.Application, string, error) {
	app, err := store.GetApp(ctx, s.store.Pool, appID)
	if errors.Is(err, store.ErrNotFound) {
		return app, "", refuse(404, "NOT_FOUND", "Application not found")
	} else if err != nil {
		return app, "", err
	}
	if app.SCIMURL == "" {
		return app, "", refuse(409, "NO_ENDPOINT", "%s has no provisioning endpoint. Add one in its settings first.", app.Name)
	}
	token, err := s.box.Open(app.SCIMTokenEncrypted)
	return app, token, err
}

// TestConnection checks that the application's provisioning endpoint
// answers and accepts the Hub's token.
func (s *Service) TestConnection(ctx context.Context, actor, appID string) error {
	app, token, err := s.connection(ctx, appID)
	if err != nil {
		return err
	}
	if err := provisioning.CheckConnection(ctx, app.SCIMURL, token); err != nil {
		return refuse(502, "APP_UNREACHABLE", "%s's endpoint did not accept the Hub: %v", app.Name, err)
	}
	return nil
}

// ImportResult says what an import added or changed.
type ImportResult struct {
	PermissionsAdded int `json:"permissionsAdded"`
	RolesAdded       int `json:"rolesAdded"`
	RolesUpdated     int `json:"rolesUpdated"`
}

// ImportCatalog takes the application's own roles and permissions: missing
// ones are added, and each imported role gets exactly the permissions the
// application gives it. Nothing defined only in the Hub is removed. Everyone
// with access is pushed again, so the application and the Hub agree.
func (s *Service) ImportCatalog(ctx context.Context, actor, appID string) (ImportResult, error) {
	var result ImportResult
	app, token, err := s.connection(ctx, appID)
	if err != nil {
		return result, err
	}
	catalog, err := provisioning.FetchCatalog(ctx, app.SCIMURL, token)
	if err != nil {
		return result, refuse(502, "APP_UNREACHABLE", "%s did not give its roles and permissions: %v", app.Name, err)
	}

	err = s.store.Tx(ctx, func(tx pgx.Tx) error {
		permissions, err := store.ListPermissions(ctx, tx, appID)
		if err != nil {
			return err
		}
		idOf := map[string]string{}
		for _, p := range permissions {
			idOf[p.Key] = p.ID
		}
		for _, cp := range catalog.Permissions {
			if _, ok := idOf[cp.Key]; ok || !permissionKeyPattern.MatchString(cp.Key) {
				continue
			}
			name := strings.TrimSpace(cp.Name)
			if name == "" {
				name = cp.Key
			}
			created, err := store.CreatePermission(ctx, tx, store.Permission{AppID: appID, Key: cp.Key, Name: name})
			if err != nil {
				return err
			}
			idOf[cp.Key] = created.ID
			result.PermissionsAdded++
		}

		roles, err := store.ListRoles(ctx, tx, appID)
		if err != nil {
			return err
		}
		existing := map[string]store.Role{}
		for _, r := range roles {
			existing[r.Key] = r
		}
		for _, cr := range catalog.Roles {
			if !roleKeyPattern.MatchString(cr.Key) {
				continue
			}
			ids := []string{}
			for _, key := range cr.Permissions {
				if id, ok := idOf[key]; ok {
					ids = append(ids, id)
				}
			}
			if r, ok := existing[cr.Key]; ok {
				r.PermissionIDs = ids
				if err := store.UpdateRole(ctx, tx, r); err != nil {
					return err
				}
				result.RolesUpdated++
				continue
			}
			name := strings.TrimSpace(cr.Name)
			if name == "" {
				name = cr.Key
			}
			if _, err := store.CreateRole(ctx, tx, store.Role{AppID: appID, Key: cr.Key, Name: name, PermissionIDs: ids}); err != nil {
				return err
			}
			result.RolesAdded++
		}
		if err := s.pushAppUsers(ctx, tx, appID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "app.import", "application", appID,
			fmt.Sprintf("Imported %s's roles and permissions", app.Name), map[string]any{
				"permissionsAdded": result.PermissionsAdded, "rolesAdded": result.RolesAdded, "rolesUpdated": result.RolesUpdated})
	})
	if err == nil {
		s.wake()
	}
	return result, err
}

// CreateAppGroup creates the application's Asgardeo access group and puts
// everybody who has access in it.
func (s *Service) CreateAppGroup(ctx context.Context, actor, appID string) (store.Application, error) {
	app, err := store.GetApp(ctx, s.store.Pool, appID)
	if errors.Is(err, store.ErrNotFound) {
		return app, refuse(404, "NOT_FOUND", "Application not found")
	} else if err != nil {
		return app, err
	}
	if app.AsgardeoGroupID != "" {
		return app, refuse(409, "EXISTS", "The application already has an Asgardeo group")
	}
	if !s.dir.CanManageGroups(ctx) {
		return app, refuse(409, "GROUPS_NOT_AUTHORIZED",
			"The Hub's M2M application is not authorized for the SCIM2 Groups API in Asgardeo (Management APIs). Authorize it, then try again.")
	}
	name := "app-" + app.Key
	groupID, err := s.dir.CreateGroup(ctx, name)
	if err != nil {
		return app, asgardeoRefusal(err, "create the group")
	}
	if err := store.SetAppGroup(ctx, s.store.Pool, appID, groupID, name); err != nil {
		return app, err
	}
	users, err := store.UsersOfApp(ctx, s.store.Pool, appID)
	if err != nil {
		return app, err
	}
	for _, userID := range users {
		if user, err := store.GetUser(ctx, s.store.Pool, userID); err == nil {
			if err := s.dir.AddGroupMember(ctx, groupID, user.AsgardeoID); err != nil {
				s.log.Warn("adding to new Asgardeo group", "app", app.Key, "user", user.Email, "error", err)
			}
		}
	}
	_ = store.Audit(ctx, s.store.Pool, actor, "app.group", "application", appID,
		"Created Asgardeo group "+name+" for "+app.Name, map[string]any{"groupId": groupID})
	return store.GetApp(ctx, s.store.Pool, appID)
}

// DeleteApp removes an application nobody has access to any more.
func (s *Service) DeleteApp(ctx context.Context, actor, appID string) error {
	app, err := store.GetApp(ctx, s.store.Pool, appID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "NOT_FOUND", "Application not found")
	} else if err != nil {
		return err
	}
	if app.UserCount > 0 {
		return refuse(409, "IN_USE", "%d people still have access to %s. Remove their access first.", app.UserCount, app.Name)
	}
	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.DeleteApp(ctx, tx, appID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "app.delete", "application", appID, "Removed "+app.Name, nil)
	})
}

// --------------------------------------------------- permissions & roles

var permissionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{1,79}$`)
var roleKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{1,79}$`)

func (s *Service) SavePermission(ctx context.Context, actor string, p store.Permission) (store.Permission, error) {
	p.Key = strings.TrimSpace(p.Key)
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return p, refuse(400, "VALIDATION", "A name is required")
	}
	if p.ID == "" && !permissionKeyPattern.MatchString(p.Key) {
		return p, refuse(400, "VALIDATION", "The key must be lowercase, like projects:create or reports.view")
	}
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := store.GetApp(ctx, tx, p.AppID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Application not found")
		}
		var err error
		if p.ID == "" {
			p, err = store.CreatePermission(ctx, tx, p)
			if store.IsUniqueViolation(err) {
				return refuse(409, "DUPLICATE", "The application already has a permission %q", p.Key)
			}
		} else {
			err = store.UpdatePermission(ctx, tx, p)
		}
		if errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Permission not found")
		}
		if err != nil {
			return err
		}
		if err := s.pushAppUsers(ctx, tx, p.AppID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "permission.save", "application", p.AppID, "Saved permission "+p.Key, nil)
	})
	if err == nil {
		s.wake()
	}
	return p, err
}

func (s *Service) DeletePermission(ctx context.Context, actor, appID, permissionID string) error {
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.DeletePermission(ctx, tx, appID, permissionID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Permission not found")
		} else if err != nil {
			return err
		}
		if err := s.pushAppUsers(ctx, tx, appID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "permission.delete", "application", appID, "Deleted a permission", map[string]any{"permissionId": permissionID})
	})
	if err == nil {
		s.wake()
	}
	return err
}

func (s *Service) SaveRole(ctx context.Context, actor string, r store.Role) (store.Role, error) {
	r.Key = strings.TrimSpace(r.Key)
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return r, refuse(400, "VALIDATION", "A name is required")
	}
	if r.ID == "" && !roleKeyPattern.MatchString(r.Key) {
		return r, refuse(400, "VALIDATION", "The key must be letters, digits and _ . : -, like DEVELOPER")
	}
	if r.PermissionIDs == nil {
		r.PermissionIDs = []string{}
	}
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := store.GetApp(ctx, tx, r.AppID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Application not found")
		}
		var err error
		if r.ID == "" {
			r, err = store.CreateRole(ctx, tx, r)
			if store.IsUniqueViolation(err) {
				return refuse(409, "DUPLICATE", "The application already has a role %q", r.Key)
			}
		} else {
			err = store.UpdateRole(ctx, tx, r)
		}
		if errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Role not found")
		}
		if err != nil {
			return err
		}
		if err := s.pushAppUsers(ctx, tx, r.AppID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "role.save", "application", r.AppID, "Saved role "+r.Key,
			map[string]any{"permissions": r.PermissionIDs})
	})
	if err == nil {
		s.wake()
	}
	return r, err
}

func (s *Service) DeleteRole(ctx context.Context, actor, appID, roleID string) error {
	err := s.store.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.DeleteRole(ctx, tx, appID, roleID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "NOT_FOUND", "Role not found")
		} else if err != nil {
			return err
		}
		if err := s.pushAppUsers(ctx, tx, appID); err != nil {
			return err
		}
		return store.Audit(ctx, tx, actor, "role.delete", "application", appID, "Deleted a role", map[string]any{"roleId": roleID})
	})
	if err == nil {
		s.wake()
	}
	return err
}

// ------------------------------------------------------------------ sync

// SyncUsers reads every Asgardeo account into the Hub. Changes made
// outside the Hub - a lock, a new name, a deletion in the Asgardeo console -
// are pushed on to the applications the person has.
func (s *Service) SyncUsers(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	remote, err := s.dir.ListUsers(ctx)
	if err != nil {
		return asgardeoRefusal(err, "list the organization's users")
	}

	seen := make([]string, 0, len(remote))
	var changed []string
	for _, r := range remote {
		seen = append(seen, r.ID)
		before, err := store.GetUserByAsgardeoID(ctx, s.store.Pool, r.ID)
		isNew := errors.Is(err, store.ErrNotFound)
		if err != nil && !isNew {
			return err
		}
		after, err := store.UpsertUser(ctx, s.store.Pool, fromDirectory(r, "", false))
		if err != nil {
			return err
		}
		if !isNew && (before.Locked != after.Locked || before.Email != after.Email ||
			before.GivenName != after.GivenName || before.FamilyName != after.FamilyName || before.RemovedAt != nil) {
			changed = append(changed, after.ID)
		}
	}

	return s.store.Tx(ctx, func(tx pgx.Tx) error {
		// Deleted in Asgardeo since the last sync: deactivated everywhere.
		rows, err := tx.Query(ctx, `SELECT id FROM users WHERE removed_at IS NULL AND NOT (asgardeo_id = ANY($1))`, seen)
		if err != nil {
			return err
		}
		var gone []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			gone = append(gone, id)
		}
		rows.Close()
		if _, err := store.MarkRemovedExcept(ctx, tx, seen); err != nil {
			return err
		}
		for _, userID := range gone {
			grants, err := store.ListGrantsForUser(ctx, tx, userID)
			if err != nil {
				return err
			}
			for _, g := range grants {
				if err := store.SetGrantStatus(ctx, tx, userID, g.AppID, "revoking", ""); err != nil {
					return err
				}
				if err := store.EnqueueJob(ctx, tx, userID, g.AppID, "deprovision"); err != nil {
					return err
				}
			}
			_ = store.Audit(ctx, tx, "asgardeo-sync", "user.removed", "user", userID, "Removed in Asgardeo; access withdrawn", nil)
		}
		for _, userID := range changed {
			if err := s.pushToAllApps(ctx, tx, userID); err != nil {
				return err
			}
		}
		if len(gone) > 0 || len(changed) > 0 {
			defer s.wake()
		}
		return nil
	})
}

// RunSync syncs now and then every interval, until ctx ends.
func (s *Service) RunSync(ctx context.Context, every time.Duration) {
	for {
		if err := s.SyncUsers(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("syncing users from Asgardeo", "error", err)
		}
		_ = store.DeleteExpiredSessions(ctx, s.store.Pool, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// GroupsEnabled: whether Asgardeo access groups can be managed.
func (s *Service) GroupsEnabled(ctx context.Context) bool { return s.dir.CanManageGroups(ctx) }

// --------------------------------------------------------------- helpers

func (s *Service) getUser(ctx context.Context, id string) (store.User, error) {
	user, err := store.GetUser(ctx, s.store.Pool, id)
	if errors.Is(err, store.ErrNotFound) {
		return user, refuse(404, "NOT_FOUND", "User not found")
	}
	return user, err
}

func fromDirectory(r asgardeo.User, department string, createdViaHub bool) store.User {
	u := store.User{
		AsgardeoID:    r.ID,
		Username:      r.UserName,
		Email:         r.Email,
		GivenName:     r.GivenName,
		FamilyName:    r.FamilyName,
		AccountType:   r.AccountType,
		AccountState:  r.AccountState,
		Locked:        r.Locked,
		Department:    department,
		CreatedViaHub: createdViaHub,
	}
	if u.AccountType == "" {
		u.AccountType = "Customer"
	}
	if !r.Created.IsZero() {
		created := r.Created
		u.AsgardeoCreatedAt = &created
	}
	return u
}

func normalEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email[strings.LastIndex(email, "@")+1:], ".") {
		return "", refuse(400, "VALIDATION", "Enter a valid email address")
	}
	return email, nil
}

func asgardeoRefusal(err error, action string) error {
	var ae *asgardeo.Error
	if errors.As(err, &ae) {
		if ae.Unanswered {
			return refuse(504, "ASGARDEO_TIMEOUT", "Could not %s: %s", action, ae.Detail)
		}
		status := 502
		if ae.Status == 409 {
			status = 409
		}
		return refuse(status, "ASGARDEO", "Asgardeo could not %s: %s", action, ae.Detail)
	}
	return err
}
