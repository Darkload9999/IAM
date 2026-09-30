package store

import (
	"context"
	"time"
)

// EnqueueJob asks the worker to bring the person's account in the
// application up to date ("upsert") or remove it there ("deprovision").
// A job for the same person and application that has not started yet is
// replaced rather than joined by another: only the latest intent matters.
func EnqueueJob(ctx context.Context, q Q, userID, appID, operation string) error {
	tag, err := q.Exec(ctx, `UPDATE provisioning_jobs SET operation = $3, next_run_at = now(),
		last_error = '', updated_at = now()
		WHERE user_id = $1 AND app_id = $2 AND status = 'pending'`, userID, appID, operation)
	if err != nil || tag.RowsAffected() > 0 {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO provisioning_jobs (user_id, app_id, operation) VALUES ($1, $2, $3)`,
		userID, appID, operation)
	return err
}

// ClaimJobs takes up to limit due jobs for this worker. Jobs left running by
// a worker that died are taken back after five minutes.
func ClaimJobs(ctx context.Context, q Q, limit int) ([]Job, error) {
	if _, err := q.Exec(ctx, `UPDATE provisioning_jobs SET status = 'pending', updated_at = now()
		WHERE status = 'running' AND updated_at < now() - interval '5 minutes'`); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `UPDATE provisioning_jobs j SET status = 'running', attempts = attempts + 1, updated_at = now()
		WHERE j.id IN (
			SELECT id FROM provisioning_jobs
			WHERE status = 'pending' AND next_run_at <= now()
			ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT $1)
		RETURNING j.id, j.user_id, '', j.app_id, '', j.operation, j.status, j.attempts,
			j.next_run_at, j.last_error, j.created_at, j.updated_at`, limit)
	if err != nil {
		return nil, err
	}
	return scanJobs(rows)
}

func CompleteJob(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `UPDATE provisioning_jobs SET status = 'done', last_error = '', updated_at = now()
		WHERE id = $1`, id)
	return err
}

// FailJob records the error: tried again at retryAt, or given up on (failed)
// when retryAt is nil.
func FailJob(ctx context.Context, q Q, id, lastError string, retryAt *time.Time) error {
	if retryAt != nil {
		_, err := q.Exec(ctx, `UPDATE provisioning_jobs SET status = 'pending', last_error = $2,
			next_run_at = $3, updated_at = now() WHERE id = $1`, id, lastError, *retryAt)
		return err
	}
	_, err := q.Exec(ctx, `UPDATE provisioning_jobs SET status = 'failed', last_error = $2, updated_at = now()
		WHERE id = $1`, id, lastError)
	return err
}

// RetryJob puts a failed job back in the queue, from its first attempt.
func RetryJob(ctx context.Context, q Q, id string) error {
	tag, err := q.Exec(ctx, `UPDATE provisioning_jobs SET status = 'pending', attempts = 0,
		next_run_at = now(), updated_at = now() WHERE id::text = $1 AND status = 'failed'`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func ListJobs(ctx context.Context, q Q, status string, limit int) ([]Job, error) {
	rows, err := q.Query(ctx, `SELECT j.id, j.user_id, u.email, j.app_id, a.key, j.operation, j.status,
		j.attempts, j.next_run_at, j.last_error, j.created_at, j.updated_at
		FROM provisioning_jobs j JOIN users u ON u.id = j.user_id JOIN applications a ON a.id = j.app_id
		WHERE ($1 = '' OR j.status = $1)
		ORDER BY j.updated_at DESC LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	return scanJobs(rows)
}

type jobRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

func scanJobs(rows jobRows) ([]Job, error) {
	defer rows.Close()
	jobs := []Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.UserID, &j.UserEmail, &j.AppID, &j.AppKey, &j.Operation, &j.Status,
			&j.Attempts, &j.NextRunAt, &j.LastError, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}
