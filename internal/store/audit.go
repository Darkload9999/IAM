package store

import (
	"context"
	"encoding/json"
	"time"
)

// Audit records what an admin (or the Hub itself) did.
func Audit(ctx context.Context, q Q, actor, action, targetType, targetID, summary string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_events (actor, action, target_type, target_id, summary, details)
		VALUES ($1, $2, $3, $4, $5, $6)`, actor, action, targetType, targetID, summary, raw)
	return err
}

func ListAudit(ctx context.Context, q Q, targetID string, limit int) ([]AuditEvent, error) {
	rows, err := q.Query(ctx, `SELECT id, actor, action, target_type, target_id, summary, details, created_at
		FROM audit_events WHERE ($1 = '' OR target_id = $1) ORDER BY created_at DESC, id DESC LIMIT $2`,
		targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var raw []byte
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Summary, &raw, &e.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &e.Details)
		events = append(events, e)
	}
	return events, rows.Err()
}

func CreateSession(ctx context.Context, q Q, idHash string, s Session) error {
	_, err := q.Exec(ctx, `INSERT INTO sessions (id_hash, subject, email, name, csrf_token, id_token_encrypted, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, idHash, s.Subject, s.Email, s.Name, s.CSRFToken, s.IDTokenEncrypted, s.ExpiresAt)
	return err
}

// GetSession returns a live session and notes that it was used.
func GetSession(ctx context.Context, q Q, idHash string) (Session, error) {
	var s Session
	err := q.QueryRow(ctx, `UPDATE sessions SET last_seen = now()
		WHERE id_hash = $1 AND expires_at > now()
		RETURNING subject, email, name, csrf_token, id_token_encrypted, expires_at`, idHash).
		Scan(&s.Subject, &s.Email, &s.Name, &s.CSRFToken, &s.IDTokenEncrypted, &s.ExpiresAt)
	return s, notFound(err)
}

func DeleteSession(ctx context.Context, q Q, idHash string) error {
	_, err := q.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
	return err
}

func DeleteExpiredSessions(ctx context.Context, q Q, now time.Time) error {
	_, err := q.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	return err
}

type HubAdmin struct {
	Email     string    `json:"email"`
	UserID    string    `json:"userId"`
	Name      string    `json:"name"`
	AddedBy   string    `json:"addedBy"`
	CreatedAt time.Time `json:"createdAt"`
}

func ListHubAdmins(ctx context.Context, q Q) ([]HubAdmin, error) {
	rows, err := q.Query(ctx, `SELECT u.email, h.user_id, trim(u.given_name || ' ' || u.family_name), h.added_by, h.created_at
		FROM hub_admins h JOIN users u ON u.id = h.user_id ORDER BY u.email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []HubAdmin{}
	for rows.Next() {
		var a HubAdmin
		if err := rows.Scan(&a.Email, &a.UserID, &a.Name, &a.AddedBy, &a.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// IsHubAdmin: whether the owner appointed this account (by its Hub id).
func IsHubAdmin(ctx context.Context, q Q, userID string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hub_admins WHERE user_id::text = $1)`, userID).Scan(&ok)
	return ok, err
}

func AddHubAdmin(ctx context.Context, q Q, userID, email, addedBy string) error {
	_, err := q.Exec(ctx, `INSERT INTO hub_admins (email, user_id, added_by) VALUES (lower($1), $2, $3)
		ON CONFLICT DO NOTHING`, email, userID, addedBy)
	return err
}

func RemoveHubAdmin(ctx context.Context, q Q, userID string) error {
	tag, err := q.Exec(ctx, `DELETE FROM hub_admins WHERE user_id::text = $1`, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
