// Package store is the Hub's data access: plain SQL over pgx.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Q is what both the pool and a transaction offer, so every query can run
// inside or outside one.
type Q interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Store struct{ Pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// Tx runs fn in a transaction, committed when fn returns nil.
func (s *Store) Tx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.Pool, fn)
}

var ErrNotFound = errors.New("not found")

// IsUniqueViolation reports a duplicate key.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsCheckViolation reports a value a CHECK constraint refused.
func IsCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

type User struct {
	ID                string     `json:"id"`
	AsgardeoID        string     `json:"asgardeoId"`
	Username          string     `json:"username"`
	Email             string     `json:"email"`
	GivenName         string     `json:"givenName"`
	FamilyName        string     `json:"familyName"`
	AccountType       string     `json:"accountType"`
	AccountState      string     `json:"accountState"`
	Locked            bool       `json:"locked"`
	Department        string     `json:"department"`
	CreatedViaHub     bool       `json:"createdViaHub"`
	AsgardeoCreatedAt *time.Time `json:"asgardeoCreatedAt"`
	RemovedAt         *time.Time `json:"removedAt"`
	SyncedAt          time.Time  `json:"syncedAt"`
	CreatedAt         time.Time  `json:"createdAt"`
	// Keys of the applications the person has access to (lists only).
	Apps []string `json:"apps,omitempty"`
}

type Application struct {
	ID                string    `json:"id"`
	Key               string    `json:"key"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	URL               string    `json:"url"`
	SCIMURL           string    `json:"scimUrl"`
	HasSCIMToken      bool      `json:"hasScimToken"`
	AsgardeoGroupID   string    `json:"asgardeoGroupId"`
	AsgardeoGroupName string    `json:"asgardeoGroupName"`
	UserCount         int       `json:"userCount"`
	CreatedAt         time.Time `json:"createdAt"`
	// Kept out of every answer; the provisioning worker reads it.
	SCIMTokenEncrypted string `json:"-"`
}

type Permission struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Role struct {
	ID            string   `json:"id"`
	AppID         string   `json:"appId"`
	Key           string   `json:"key"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permissionIds"`
}

type Grant struct {
	ID            string     `json:"id"`
	UserID        string     `json:"userId"`
	AppID         string     `json:"appId"`
	AppKey        string     `json:"appKey"`
	AppName       string     `json:"appName"`
	RemoteID      string     `json:"remoteId"`
	SyncStatus    string     `json:"syncStatus"`
	LastError     string     `json:"lastError"`
	LastSyncedAt  *time.Time `json:"lastSyncedAt"`
	GrantedBy     string     `json:"grantedBy"`
	CreatedAt     time.Time  `json:"createdAt"`
	RoleIDs       []string   `json:"roleIds"`
	PermissionIDs []string   `json:"permissionIds"`
	// Every permission key the person holds in the application: through
	// their roles, and given directly.
	EffectivePermissions []string `json:"effectivePermissions"`
}

type Job struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	UserEmail string    `json:"userEmail"`
	AppID     string    `json:"appId"`
	AppKey    string    `json:"appKey"`
	Operation string    `json:"operation"`
	Status    string    `json:"status"`
	Attempts  int       `json:"attempts"`
	NextRunAt time.Time `json:"nextRunAt"`
	LastError string    `json:"lastError"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type AuditEvent struct {
	ID         int64          `json:"id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"targetType"`
	TargetID   string         `json:"targetId"`
	Summary    string         `json:"summary"`
	Details    map[string]any `json:"details"`
	CreatedAt  time.Time      `json:"createdAt"`
}

type Session struct {
	Subject   string
	Email     string
	Name      string
	CSRFToken string
	// Sent to Asgardeo as id_token_hint on sign-out.
	IDTokenEncrypted string
	ExpiresAt        time.Time
}
