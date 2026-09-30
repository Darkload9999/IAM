package web

import (
	"net/http"
	"strconv"

	"github.com/zeit26/identity-hub/internal/hub"
	"github.com/zeit26/identity-hub/internal/store"
)

// actor is how the audit log names whoever made a change.
func actor(p *principal) string { return p.User.Email }

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request, p *principal) error {
	writeJSON(w, http.StatusOK, map[string]any{
		"userId":       p.User.ID,
		"email":        p.User.Email,
		"name":         p.Session.Name,
		"role":         p.Role,
		"csrfToken":    p.Session.CSRFToken,
		"expiresAt":    p.Session.ExpiresAt,
		"organization": s.opts.Organization,
	})
	return nil
}

func (s *Server) apiOverview(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	stats, err := store.GetStats(ctx, s.store.Pool)
	if err != nil {
		return err
	}
	stats.GroupsEnabled = s.svc.GroupsEnabled(ctx)
	stats.OrganizationOwner, _ = store.OwnerEmail(ctx, s.store.Pool)
	failed, err := store.ListJobs(ctx, s.store.Pool, "failed", 10)
	if err != nil {
		return err
	}
	recent, err := store.ListAudit(ctx, s.store.Pool, "", 12)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": stats, "failedJobs": failed, "recentActivity": recent})
	return nil
}

func (s *Server) apiSync(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.SyncUsers(r.Context()); err != nil {
		return err
	}
	_ = store.Audit(r.Context(), s.store.Pool, actor(p), "sync.run", "system", "", "Synced users from Asgardeo", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// ---------------------------------------------------------------- users

func (s *Server) apiListUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	q := r.URL.Query()
	users, err := store.ListUsers(r.Context(), s.store.Pool, store.UserFilter{
		Search: q.Get("search"), AccountType: q.Get("type"), Status: q.Get("status"), AppID: q.Get("app"),
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
	return nil
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in hub.NewUser
	if err := readJSON(r, &in); err != nil {
		return err
	}
	created, err := s.svc.CreateUser(r.Context(), actor(p), in)
	if err != nil && created == nil {
		return err
	}
	body := map[string]any{"user": created.User, "invitation": created.Invitation}
	if err != nil {
		// The account exists; say what did not work alongside it.
		body["warning"] = err.Error()
	}
	writeJSON(w, http.StatusCreated, body)
	return nil
}

func (s *Server) apiGetUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	id := r.PathValue("id")
	user, err := store.GetUser(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	grants, err := store.ListGrantsForUser(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	audit, err := store.ListAudit(ctx, s.store.Pool, id, 50)
	if err != nil {
		return err
	}
	isAdmin, err := store.IsHubAdmin(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	isOwner, err := s.svc.IsOwnerAccount(ctx, user)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": user, "grants": grants, "activity": audit,
		"hubAdmin": isAdmin || isOwner, "ownerAccount": isOwner,
	})
	return nil
}

func (s *Server) apiUpdateUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in hub.UserUpdate
	if err := readJSON(r, &in); err != nil {
		return err
	}
	user, err := s.svc.UpdateUser(r.Context(), actor(p), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
	return nil
}

func (s *Server) apiLockUser(locked bool) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		if r.PathValue("id") == p.User.ID {
			return &hub.Error{Status: http.StatusConflict, Code: "PROTECTED", Message: "You cannot suspend your own account"}
		}
		user, err := s.svc.SetLocked(r.Context(), actor(p), r.PathValue("id"), locked)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
		return nil
	}
}

func (s *Server) apiDeleteUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	if r.PathValue("id") == p.User.ID {
		return &hub.Error{Status: http.StatusConflict, Code: "PROTECTED", Message: "You cannot delete your own account"}
	}
	if err := s.svc.DeleteUser(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) apiSetAccess(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		RoleIDs       []string `json:"roleIds"`
		PermissionIDs []string `json:"permissionIds"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	userID, appID := r.PathValue("id"), r.PathValue("appId")
	if err := s.svc.SetAccess(ctx, actor(p), userID, hub.AccessInput{
		AppID: appID, RoleIDs: orEmpty(in.RoleIDs), PermissionIDs: orEmpty(in.PermissionIDs),
	}); err != nil {
		return err
	}
	grant, err := store.GetGrant(ctx, s.store.Pool, userID, appID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": grant})
	return nil
}

func (s *Server) apiRevokeAccess(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.RevokeAccess(r.Context(), actor(p), r.PathValue("id"), r.PathValue("appId")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------- applications

type catalogApp struct {
	store.Application
	Permissions []store.Permission `json:"permissions"`
	Roles       []store.Role       `json:"roles"`
}

// apiCatalog: every application with its roles and permissions, for the
// access editor.
func (s *Server) apiCatalog(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	apps, err := store.ListApps(ctx, s.store.Pool)
	if err != nil {
		return err
	}
	out := make([]catalogApp, 0, len(apps))
	for _, a := range apps {
		c := catalogApp{Application: a}
		if c.Permissions, err = store.ListPermissions(ctx, s.store.Pool, a.ID); err != nil {
			return err
		}
		if c.Roles, err = store.ListRoles(ctx, s.store.Pool, a.ID); err != nil {
			return err
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
	return nil
}

func (s *Server) apiListApps(w http.ResponseWriter, r *http.Request, p *principal) error {
	apps, err := store.ListApps(r.Context(), s.store.Pool)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps, "groupsEnabled": s.svc.GroupsEnabled(r.Context())})
	return nil
}

func (s *Server) apiCreateApp(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in hub.AppInput
	if err := readJSON(r, &in); err != nil {
		return err
	}
	app, token, err := s.svc.CreateApp(r.Context(), actor(p), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"app": app, "scimToken": token})
	return nil
}

func (s *Server) apiGetApp(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	id := r.PathValue("id")
	app, err := store.GetApp(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	permissions, err := store.ListPermissions(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	roles, err := store.ListRoles(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	users, err := store.ListUsers(ctx, s.store.Pool, store.UserFilter{AppID: id, Status: "all"})
	if err != nil {
		return err
	}
	grants, err := store.ListGrantsForApp(ctx, s.store.Pool, id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app": app, "permissions": permissions, "roles": roles, "users": users, "grants": grants,
		"groupsEnabled": s.svc.GroupsEnabled(ctx),
	})
	return nil
}

func (s *Server) apiUpdateApp(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in hub.AppInput
	if err := readJSON(r, &in); err != nil {
		return err
	}
	app, err := s.svc.UpdateApp(r.Context(), actor(p), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": app})
	return nil
}

func (s *Server) apiDeleteApp(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.DeleteApp(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) apiRotateToken(w http.ResponseWriter, r *http.Request, p *principal) error {
	token, err := s.svc.RotateSCIMToken(r.Context(), actor(p), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"scimToken": token})
	return nil
}

func (s *Server) apiCreateGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	app, err := s.svc.CreateAppGroup(r.Context(), actor(p), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": app})
	return nil
}

func (s *Server) apiTestConnection(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.TestConnection(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *Server) apiImportCatalog(w http.ResponseWriter, r *http.Request, p *principal) error {
	result, err := s.svc.ImportCatalog(r.Context(), actor(p), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) apiSavePermission(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	perm, err := s.svc.SavePermission(r.Context(), actor(p), store.Permission{
		ID: r.PathValue("pid"), AppID: r.PathValue("id"), Key: in.Key, Name: in.Name, Description: in.Description,
	})
	if err != nil {
		return err
	}
	status := http.StatusOK
	if r.PathValue("pid") == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"permission": perm})
	return nil
}

func (s *Server) apiDeletePermission(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.DeletePermission(r.Context(), actor(p), r.PathValue("id"), r.PathValue("pid")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) apiSaveRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Key           string   `json:"key"`
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		PermissionIDs []string `json:"permissionIds"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	role, err := s.svc.SaveRole(r.Context(), actor(p), store.Role{
		ID: r.PathValue("rid"), AppID: r.PathValue("id"), Key: in.Key, Name: in.Name,
		Description: in.Description, PermissionIDs: orEmpty(in.PermissionIDs),
	})
	if err != nil {
		return err
	}
	status := http.StatusOK
	if r.PathValue("rid") == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"role": role})
	return nil
}

func (s *Server) apiDeleteRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.DeleteRole(r.Context(), actor(p), r.PathValue("id"), r.PathValue("rid")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ------------------------------------------------------- provisioning

func (s *Server) apiListJobs(w http.ResponseWriter, r *http.Request, p *principal) error {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "running", "done", "failed":
	default:
		return &hub.Error{Status: http.StatusBadRequest, Code: "VALIDATION", Message: "Unknown job status"}
	}
	jobs, err := store.ListJobs(r.Context(), s.store.Pool, status, limitParam(r, 200, 1000))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
	return nil
}

func (s *Server) apiRetryJob(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.RetryJob(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------- admins

func (s *Server) apiListAdmins(w http.ResponseWriter, r *http.Request, p *principal) error {
	admins, err := store.ListHubAdmins(r.Context(), s.store.Pool)
	if err != nil {
		return err
	}
	owner, _ := store.OwnerEmail(r.Context(), s.store.Pool)
	writeJSON(w, http.StatusOK, map[string]any{"owner": owner, "admins": admins})
	return nil
}

func (s *Server) apiAddAdmin(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Email string `json:"email"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	user, err := s.svc.AddAdmin(r.Context(), actor(p), in.Email)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
	return nil
}

func (s *Server) apiRemoveAdmin(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.RemoveAdmin(r.Context(), actor(p), r.PathValue("userId")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ----------------------------------------------------------------- audit

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request, p *principal) error {
	events, err := store.ListAudit(r.Context(), s.store.Pool, r.URL.Query().Get("target"), limitParam(r, 200, 1000))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
	return nil
}

func limitParam(r *http.Request, fallback, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return fallback
	}
	return min(n, max)
}

func orEmpty(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}
