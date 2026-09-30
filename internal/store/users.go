package store

import (
	"context"
	"strings"
	"time"
)

const userColumns = `u.id, u.asgardeo_id, u.username, u.email, u.given_name, u.family_name,
	u.account_type, u.account_state, u.locked, u.department, u.created_via_hub,
	u.asgardeo_created_at, u.removed_at, u.synced_at, u.created_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner, extra ...any) (User, error) {
	var u User
	dest := []any{&u.ID, &u.AsgardeoID, &u.Username, &u.Email, &u.GivenName, &u.FamilyName,
		&u.AccountType, &u.AccountState, &u.Locked, &u.Department, &u.CreatedViaHub,
		&u.AsgardeoCreatedAt, &u.RemovedAt, &u.SyncedAt, &u.CreatedAt}
	err := row.Scan(append(dest, extra...)...)
	return u, err
}

// UpsertUser records an Asgardeo account as it is now, keyed by its
// Asgardeo id. The department and whether the Hub created it are the Hub's
// own and are not overwritten by a sync.
func UpsertUser(ctx context.Context, q Q, u User) (User, error) {
	row := q.QueryRow(ctx, `
		INSERT INTO users AS u (asgardeo_id, username, email, given_name, family_name,
			account_type, account_state, locked, department, created_via_hub,
			asgardeo_created_at, removed_at, synced_at)
		VALUES ($1, $2, lower($3), $4, $5, $6, $7, $8, $9, $10, $11, NULL, now())
		ON CONFLICT (asgardeo_id) DO UPDATE SET
			username = EXCLUDED.username, email = EXCLUDED.email,
			given_name = EXCLUDED.given_name, family_name = EXCLUDED.family_name,
			account_type = EXCLUDED.account_type, account_state = EXCLUDED.account_state,
			locked = EXCLUDED.locked,
			department = CASE WHEN EXCLUDED.department <> '' THEN EXCLUDED.department ELSE u.department END,
			created_via_hub = u.created_via_hub OR EXCLUDED.created_via_hub,
			asgardeo_created_at = COALESCE(EXCLUDED.asgardeo_created_at, u.asgardeo_created_at),
			removed_at = NULL, synced_at = now(), updated_at = now()
		RETURNING `+userColumns,
		u.AsgardeoID, u.Username, u.Email, u.GivenName, u.FamilyName,
		u.AccountType, u.AccountState, u.Locked, u.Department, u.CreatedViaHub, u.AsgardeoCreatedAt)
	return scanUser(row)
}

// MarkRemovedExcept flags every account not seen in the latest sync.
func MarkRemovedExcept(ctx context.Context, q Q, seenAsgardeoIDs []string) (int64, error) {
	tag, err := q.Exec(ctx, `
		UPDATE users SET removed_at = now(), updated_at = now()
		WHERE removed_at IS NULL AND NOT (asgardeo_id = ANY($1))`, seenAsgardeoIDs)
	return tag.RowsAffected(), err
}

type UserFilter struct {
	Search      string
	AccountType string // "", Owner, Administrator, Customer
	Status      string // "", active, locked, pending, removed
	AppID       string
}

// ListUsers returns every account, each with the applications it can use.
func ListUsers(ctx context.Context, q Q, f UserFilter) ([]User, error) {
	sql := `SELECT ` + userColumns + `,
		COALESCE(array_agg(a.key ORDER BY a.key) FILTER (WHERE a.key IS NOT NULL), '{}')
		FROM users u
		LEFT JOIN access_grants g ON g.user_id = u.id
		LEFT JOIN applications a ON a.id = g.app_id
		WHERE ($1 = '' OR u.email ILIKE '%' || $1 || '%' OR (u.given_name || ' ' || u.family_name) ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR u.account_type = $2)
		  AND (
			($3 = '' AND u.removed_at IS NULL)
			OR ($3 = 'active'  AND u.removed_at IS NULL AND NOT u.locked AND u.account_state <> 'PENDING_AP')
			OR ($3 = 'locked'  AND u.removed_at IS NULL AND u.locked)
			OR ($3 = 'pending' AND u.removed_at IS NULL AND u.account_state = 'PENDING_AP')
			OR ($3 = 'removed' AND u.removed_at IS NOT NULL)
			OR ($3 = 'all')
		  )
		  AND ($4 = '' OR EXISTS (SELECT 1 FROM access_grants x WHERE x.user_id = u.id AND x.app_id::text = $4))
		GROUP BY u.id
		ORDER BY (u.account_type = 'Owner') DESC, lower(u.email)`
	rows, err := q.Query(ctx, sql, strings.TrimSpace(f.Search), f.AccountType, f.Status, f.AppID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var apps []string
		u, err := scanUser(rows, &apps)
		if err != nil {
			return nil, err
		}
		u.Apps = apps
		users = append(users, u)
	}
	return users, rows.Err()
}

func GetUser(ctx context.Context, q Q, id string) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE u.id::text = $1`, id))
	return u, notFound(err)
}

func GetUserByAsgardeoID(ctx context.Context, q Q, asgardeoID string) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE u.asgardeo_id = $1`, asgardeoID))
	return u, notFound(err)
}

// GetUserBySubject finds the account an ID token's subject names: Asgardeo's
// user id by default, or the username when the application is set to use it.
func GetUserBySubject(ctx context.Context, q Q, subject string) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM users u
		WHERE u.removed_at IS NULL
		  AND (u.asgardeo_id = $1 OR u.username = $1 OR u.username = $2)
		ORDER BY (u.asgardeo_id = $1) DESC LIMIT 1`, subject, "DEFAULT/"+subject))
	return u, notFound(err)
}

// GetActiveUserByEmail: the live account with this address, if exactly one.
func GetActiveUserByEmail(ctx context.Context, q Q, email string) (User, error) {
	rows, err := q.Query(ctx, `SELECT `+userColumns+` FROM users u
		WHERE u.removed_at IS NULL AND u.email = lower($1) LIMIT 2`, email)
	if err != nil {
		return User{}, err
	}
	defer rows.Close()
	var found []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return User{}, err
		}
		found = append(found, u)
	}
	if err := rows.Err(); err != nil {
		return User{}, err
	}
	if len(found) != 1 {
		return User{}, ErrNotFound
	}
	return found[0], nil
}

func UpdateUserProfile(ctx context.Context, q Q, id, givenName, familyName, department string) error {
	tag, err := q.Exec(ctx, `UPDATE users SET given_name = $2, family_name = $3, department = $4, updated_at = now()
		WHERE id::text = $1`, id, givenName, familyName, department)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func SetUserLocked(ctx context.Context, q Q, id string, locked bool) error {
	state := "UNLOCKED"
	if locked {
		state = "LOCKED"
	}
	_, err := q.Exec(ctx, `UPDATE users SET locked = $2,
		account_state = CASE WHEN account_state = 'PENDING_AP' AND NOT $2 THEN account_state ELSE $3 END,
		updated_at = now() WHERE id::text = $1`, id, locked, state)
	return err
}

func DeleteUser(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM users WHERE id::text = $1`, id)
	return err
}

// OwnerUsername is the organization owner's username (it has no user store
// prefix: the owner lives outside the organization's user store).
func OwnerUsername(ctx context.Context, q Q) (string, error) {
	var username string
	err := q.QueryRow(ctx, `SELECT username FROM users WHERE account_type = 'Owner' AND removed_at IS NULL
		ORDER BY synced_at DESC LIMIT 1`).Scan(&username)
	return username, notFound(err)
}

// OwnerEmail is the organization owner's address, as last synced.
func OwnerEmail(ctx context.Context, q Q) (string, error) {
	var email string
	err := q.QueryRow(ctx, `SELECT email FROM users WHERE account_type = 'Owner' AND removed_at IS NULL
		ORDER BY synced_at DESC LIMIT 1`).Scan(&email)
	return email, notFound(err)
}

type Stats struct {
	Users             int        `json:"users"`
	Pending           int        `json:"pending"`
	Locked            int        `json:"locked"`
	Applications      int        `json:"applications"`
	Grants            int        `json:"grants"`
	JobsPending       int        `json:"jobsPending"`
	JobsFailed        int        `json:"jobsFailed"`
	LastSyncedAt      *time.Time `json:"lastSyncedAt"`
	GroupsEnabled     bool       `json:"groupsEnabled"`
	OrganizationOwner string     `json:"organizationOwner"`
}

func GetStats(ctx context.Context, q Q) (Stats, error) {
	var s Stats
	err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM users WHERE removed_at IS NULL),
		(SELECT count(*) FROM users WHERE removed_at IS NULL AND account_state = 'PENDING_AP'),
		(SELECT count(*) FROM users WHERE removed_at IS NULL AND locked),
		(SELECT count(*) FROM applications),
		(SELECT count(*) FROM access_grants),
		(SELECT count(*) FROM provisioning_jobs WHERE status IN ('pending', 'running')),
		(SELECT count(*) FROM provisioning_jobs WHERE status = 'failed'),
		(SELECT max(synced_at) FROM users)`).Scan(
		&s.Users, &s.Pending, &s.Locked, &s.Applications, &s.Grants, &s.JobsPending, &s.JobsFailed, &s.LastSyncedAt)
	return s, err
}
