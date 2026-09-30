package store

import (
	"context"
	"time"
)

const grantSelect = `SELECT g.id, g.user_id, g.app_id, a.key, a.name, g.remote_id, g.sync_status,
	g.last_error, g.last_synced_at, g.granted_by, g.created_at,
	COALESCE((SELECT array_agg(gr.role_id::text) FROM grant_roles gr WHERE gr.grant_id = g.id), '{}'),
	COALESCE((SELECT array_agg(gp.permission_id::text) FROM grant_permissions gp WHERE gp.grant_id = g.id), '{}'),
	COALESCE((SELECT array_agg(DISTINCT p.key ORDER BY p.key) FROM permissions p
		WHERE p.id IN (SELECT rp.permission_id FROM grant_roles gr JOIN role_permissions rp ON rp.role_id = gr.role_id WHERE gr.grant_id = g.id)
		   OR p.id IN (SELECT gp.permission_id FROM grant_permissions gp WHERE gp.grant_id = g.id)), '{}')
	FROM access_grants g JOIN applications a ON a.id = g.app_id`

func scanGrant(row scanner) (Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.UserID, &g.AppID, &g.AppKey, &g.AppName, &g.RemoteID, &g.SyncStatus,
		&g.LastError, &g.LastSyncedAt, &g.GrantedBy, &g.CreatedAt, &g.RoleIDs, &g.PermissionIDs,
		&g.EffectivePermissions)
	return g, err
}

func ListGrantsForUser(ctx context.Context, q Q, userID string) ([]Grant, error) {
	return listGrants(ctx, q, grantSelect+` WHERE g.user_id::text = $1 ORDER BY lower(a.name)`, userID)
}

func ListGrantsForApp(ctx context.Context, q Q, appID string) ([]Grant, error) {
	return listGrants(ctx, q, grantSelect+` WHERE g.app_id::text = $1 ORDER BY g.created_at`, appID)
}

func listGrants(ctx context.Context, q Q, sql string, args ...any) ([]Grant, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Grant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, g)
	}
	return list, rows.Err()
}

func GetGrant(ctx context.Context, q Q, userID, appID string) (Grant, error) {
	g, err := scanGrant(q.QueryRow(ctx, grantSelect+` WHERE g.user_id::text = $1 AND g.app_id::text = $2`, userID, appID))
	return g, notFound(err)
}

// UpsertGrant gives (or keeps) the person access to the application with
// exactly these roles and direct permissions - only ones belonging to that
// application are taken - and marks it for provisioning.
func UpsertGrant(ctx context.Context, q Q, userID, appID, grantedBy string, roleIDs, permissionIDs []string) (string, error) {
	var grantID string
	if err := q.QueryRow(ctx, `INSERT INTO access_grants (user_id, app_id, granted_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, app_id) DO UPDATE SET sync_status = 'pending', updated_at = now()
		RETURNING id`, userID, appID, grantedBy).Scan(&grantID); err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `DELETE FROM grant_roles WHERE grant_id = $1`, grantID); err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `INSERT INTO grant_roles (grant_id, role_id)
		SELECT $1, r.id FROM roles r WHERE r.app_id = $2 AND r.id::text = ANY($3)`, grantID, appID, roleIDs); err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `DELETE FROM grant_permissions WHERE grant_id = $1`, grantID); err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `INSERT INTO grant_permissions (grant_id, permission_id)
		SELECT $1, p.id FROM permissions p WHERE p.app_id = $2 AND p.id::text = ANY($3)`, grantID, appID, permissionIDs); err != nil {
		return "", err
	}
	return grantID, nil
}

func SetGrantStatus(ctx context.Context, q Q, userID, appID, status, lastError string) error {
	_, err := q.Exec(ctx, `UPDATE access_grants SET sync_status = $3, last_error = $4, updated_at = now()
		WHERE user_id = $1 AND app_id = $2`, userID, appID, status, lastError)
	return err
}

func MarkGrantProvisioned(ctx context.Context, q Q, userID, appID, remoteID string, at time.Time) error {
	_, err := q.Exec(ctx, `UPDATE access_grants SET sync_status = 'provisioned', last_error = '',
		remote_id = CASE WHEN $3 <> '' THEN $3 ELSE remote_id END, last_synced_at = $4, updated_at = now()
		WHERE user_id = $1 AND app_id = $2`, userID, appID, remoteID, at)
	return err
}

// DeleteRevokingGrant removes a grant on its way out - but not one that was
// given again while it was being taken away.
func DeleteRevokingGrant(ctx context.Context, q Q, userID, appID string) error {
	_, err := q.Exec(ctx, `DELETE FROM access_grants WHERE user_id = $1 AND app_id = $2
		AND sync_status = 'revoking'`, userID, appID)
	return err
}

// UsersWithRole: everybody whose access to the role's application includes
// the role - they are provisioned again when the role changes.
func UsersWithRole(ctx context.Context, q Q, roleID string) ([]string, string, error) {
	var appID string
	if err := q.QueryRow(ctx, `SELECT app_id FROM roles WHERE id::text = $1`, roleID).Scan(&appID); err != nil {
		return nil, "", notFound(err)
	}
	rows, err := q.Query(ctx, `SELECT g.user_id FROM grant_roles gr JOIN access_grants g ON g.id = gr.grant_id
		WHERE gr.role_id::text = $1`, roleID)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, "", err
		}
		users = append(users, id)
	}
	return users, appID, rows.Err()
}

// UsersOfApp: everybody with access to the application.
func UsersOfApp(ctx context.Context, q Q, appID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT user_id FROM access_grants WHERE app_id::text = $1`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		users = append(users, id)
	}
	return users, rows.Err()
}

// ProvisioningView is everything the worker sends to an application about
// one person.
type ProvisioningView struct {
	User        User
	App         Application
	Grant       *Grant
	Roles       []Role
	Permissions []Permission
}

func LoadProvisioningView(ctx context.Context, q Q, userID, appID string) (ProvisioningView, error) {
	var v ProvisioningView
	var err error
	if v.User, err = GetUser(ctx, q, userID); err != nil {
		return v, err
	}
	if v.App, err = GetApp(ctx, q, appID); err != nil {
		return v, err
	}
	grant, err := GetGrant(ctx, q, userID, appID)
	if err == ErrNotFound {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.Grant = &grant

	rows, err := q.Query(ctx, `SELECT r.id, r.app_id, r.key, r.name, r.description FROM roles r
		JOIN grant_roles gr ON gr.role_id = r.id WHERE gr.grant_id::text = $1 ORDER BY r.key`, grant.ID)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.AppID, &r.Key, &r.Name, &r.Description); err != nil {
			rows.Close()
			return v, err
		}
		v.Roles = append(v.Roles, r)
	}
	rows.Close()

	rows, err = q.Query(ctx, `SELECT id, app_id, key, name, description FROM permissions
		WHERE key = ANY($1) AND app_id::text = $2 ORDER BY key`, grant.EffectivePermissions, appID)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.AppID, &p.Key, &p.Name, &p.Description); err != nil {
			return v, err
		}
		v.Permissions = append(v.Permissions, p)
	}
	return v, rows.Err()
}
