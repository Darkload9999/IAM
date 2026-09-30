package store

import "context"

const appColumns = `a.id, a.key, a.name, a.description, a.url, a.scim_url,
	a.scim_token_encrypted <> '', a.asgardeo_group_id, a.asgardeo_group_name,
	(SELECT count(*) FROM access_grants g WHERE g.app_id = a.id), a.created_at, a.scim_token_encrypted`

func scanApp(row scanner) (Application, error) {
	var a Application
	err := row.Scan(&a.ID, &a.Key, &a.Name, &a.Description, &a.URL, &a.SCIMURL,
		&a.HasSCIMToken, &a.AsgardeoGroupID, &a.AsgardeoGroupName, &a.UserCount, &a.CreatedAt,
		&a.SCIMTokenEncrypted)
	return a, err
}

func ListApps(ctx context.Context, q Q) ([]Application, error) {
	rows, err := q.Query(ctx, `SELECT `+appColumns+` FROM applications a ORDER BY lower(a.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []Application{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func GetApp(ctx context.Context, q Q, id string) (Application, error) {
	a, err := scanApp(q.QueryRow(ctx, `SELECT `+appColumns+` FROM applications a WHERE a.id::text = $1`, id))
	return a, notFound(err)
}

func CreateApp(ctx context.Context, q Q, a Application) (Application, error) {
	var id string
	if err := q.QueryRow(ctx, `INSERT INTO applications (key, name, description, url, scim_url, scim_token_encrypted)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		a.Key, a.Name, a.Description, a.URL, a.SCIMURL, a.SCIMTokenEncrypted).Scan(&id); err != nil {
		return Application{}, err
	}
	return GetApp(ctx, q, id)
}

// UpdateApp saves the editable fields; the SCIM token only when given.
func UpdateApp(ctx context.Context, q Q, a Application, newTokenEncrypted *string) error {
	tag, err := q.Exec(ctx, `UPDATE applications SET name = $2, description = $3, url = $4, scim_url = $5,
		scim_token_encrypted = COALESCE($6, scim_token_encrypted), updated_at = now()
		WHERE id::text = $1`, a.ID, a.Name, a.Description, a.URL, a.SCIMURL, newTokenEncrypted)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func SetAppGroup(ctx context.Context, q Q, appID, groupID, groupName string) error {
	_, err := q.Exec(ctx, `UPDATE applications SET asgardeo_group_id = $2, asgardeo_group_name = $3,
		updated_at = now() WHERE id::text = $1`, appID, groupID, groupName)
	return err
}

func DeleteApp(ctx context.Context, q Q, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM applications WHERE id::text = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func ListPermissions(ctx context.Context, q Q, appID string) ([]Permission, error) {
	rows, err := q.Query(ctx, `SELECT id, app_id, key, name, description FROM permissions
		WHERE app_id::text = $1 ORDER BY key`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Permission{}
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.AppID, &p.Key, &p.Name, &p.Description); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func CreatePermission(ctx context.Context, q Q, p Permission) (Permission, error) {
	err := q.QueryRow(ctx, `INSERT INTO permissions (app_id, key, name, description) VALUES ($1, $2, $3, $4)
		RETURNING id`, p.AppID, p.Key, p.Name, p.Description).Scan(&p.ID)
	return p, err
}

func UpdatePermission(ctx context.Context, q Q, p Permission) error {
	tag, err := q.Exec(ctx, `UPDATE permissions SET name = $3, description = $4
		WHERE id::text = $1 AND app_id::text = $2`, p.ID, p.AppID, p.Name, p.Description)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func DeletePermission(ctx context.Context, q Q, appID, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM permissions WHERE id::text = $1 AND app_id::text = $2`, id, appID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func ListRoles(ctx context.Context, q Q, appID string) ([]Role, error) {
	rows, err := q.Query(ctx, `SELECT r.id, r.app_id, r.key, r.name, r.description,
		COALESCE(array_agg(rp.permission_id::text) FILTER (WHERE rp.permission_id IS NOT NULL), '{}')
		FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE r.app_id::text = $1 GROUP BY r.id ORDER BY r.key`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.AppID, &r.Key, &r.Name, &r.Description, &r.PermissionIDs); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func CreateRole(ctx context.Context, q Q, r Role) (Role, error) {
	if err := q.QueryRow(ctx, `INSERT INTO roles (app_id, key, name, description) VALUES ($1, $2, $3, $4)
		RETURNING id`, r.AppID, r.Key, r.Name, r.Description).Scan(&r.ID); err != nil {
		return Role{}, err
	}
	return r, SetRolePermissions(ctx, q, r.AppID, r.ID, r.PermissionIDs)
}

func UpdateRole(ctx context.Context, q Q, r Role) error {
	tag, err := q.Exec(ctx, `UPDATE roles SET name = $3, description = $4
		WHERE id::text = $1 AND app_id::text = $2`, r.ID, r.AppID, r.Name, r.Description)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return SetRolePermissions(ctx, q, r.AppID, r.ID, r.PermissionIDs)
}

// SetRolePermissions replaces a role's permissions with those given, taking
// only permissions of the role's own application.
func SetRolePermissions(ctx context.Context, q Q, appID, roleID string, permissionIDs []string) error {
	if _, err := q.Exec(ctx, `DELETE FROM role_permissions WHERE role_id::text = $1`, roleID); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT $1::uuid, p.id FROM permissions p WHERE p.app_id::text = $2 AND p.id::text = ANY($3)`,
		roleID, appID, permissionIDs)
	return err
}

func DeleteRole(ctx context.Context, q Q, appID, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM roles WHERE id::text = $1 AND app_id::text = $2`, id, appID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
