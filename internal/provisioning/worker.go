package provisioning

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/zeit26/identity-hub/internal/secrets"
	"github.com/zeit26/identity-hub/internal/store"
)

// Backoff between attempts; after the last one a job is marked failed and
// waits for an admin to retry it from the dashboard.
var backoff = []time.Duration{
	15 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour,
}

type Worker struct {
	store  *store.Store
	box    *secrets.Box
	scim   *scimClient
	log    *slog.Logger
	poll   time.Duration
	notify chan struct{}
}

func NewWorker(s *store.Store, box *secrets.Box, log *slog.Logger) *Worker {
	return &Worker{
		store:  s,
		box:    box,
		scim:   newSCIMClient(),
		log:    log,
		poll:   3 * time.Second,
		notify: make(chan struct{}, 1),
	}
}

// Wake has the worker look for jobs now rather than at its next poll.
func (w *Worker) Wake() {
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// Run works through due jobs until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		w.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-w.notify:
		}
	}
}

// RunOnce claims and processes the jobs that are due now.
func (w *Worker) RunOnce(ctx context.Context) {
	for ctx.Err() == nil {
		jobs, err := store.ClaimJobs(ctx, w.store.Pool, 10)
		if err != nil {
			w.log.Error("claiming provisioning jobs", "error", err)
			return
		}
		if len(jobs) == 0 {
			return
		}
		for _, job := range jobs {
			w.process(ctx, job)
		}
	}
}

func (w *Worker) process(ctx context.Context, job store.Job) {
	jobCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	err := w.apply(jobCtx, job)
	if err == nil {
		if err := store.CompleteJob(ctx, w.store.Pool, job.ID); err != nil {
			w.log.Error("completing job", "job", job.ID, "error", err)
		}
		return
	}

	var retryAt *time.Time
	var pe *PushError
	permanent := errors.As(err, &pe) && pe.Permanent()
	if !permanent && job.Attempts <= len(backoff) {
		at := time.Now().Add(backoff[job.Attempts-1])
		retryAt = &at
	}
	w.log.Warn("provisioning failed", "job", job.ID, "user", job.UserID, "app", job.AppID,
		"operation", job.Operation, "attempt", job.Attempts, "willRetry", retryAt != nil, "error", err)

	if err := store.FailJob(ctx, w.store.Pool, job.ID, err.Error(), retryAt); err != nil {
		w.log.Error("recording job failure", "job", job.ID, "error", err)
	}
	status := "pending"
	if job.Operation == "deprovision" {
		// Still on its way out: shown as such, with the reason it is stuck.
		status = "revoking"
	} else if retryAt == nil {
		status = "failed"
	}
	_ = store.SetGrantStatus(ctx, w.store.Pool, job.UserID, job.AppID, status, err.Error())
}

func (w *Worker) apply(ctx context.Context, job store.Job) error {
	view, err := store.LoadProvisioningView(ctx, w.store.Pool, job.UserID, job.AppID)
	if errors.Is(err, store.ErrNotFound) {
		// The person or the application is gone: nothing left to do.
		return nil
	}
	if err != nil {
		return err
	}

	token, err := w.box.Open(view.App.SCIMTokenEncrypted)
	if err != nil {
		return &PushError{Detail: err.Error()}
	}

	// A deprovision job whose grant was given again meanwhile (no longer
	// "revoking") pushes the access instead of taking it away.
	deprovision := view.Grant == nil || (job.Operation == "deprovision" && view.Grant.SyncStatus == "revoking")
	remoteID := ""
	if view.Grant != nil {
		remoteID = view.Grant.RemoteID
	}

	if view.App.SCIMURL == "" {
		// The application takes no pushes: access is only its Asgardeo group.
		if deprovision {
			return store.DeleteRevokingGrant(ctx, w.store.Pool, job.UserID, job.AppID)
		}
		return store.SetGrantStatus(ctx, w.store.Pool, job.UserID, job.AppID, "not_required", "")
	}

	if deprovision {
		// Deactivated in the application (its records of the person's work
		// stay intact); the Hub's grant goes with it.
		if err := w.scim.deactivate(ctx, view.App.SCIMURL, token, remoteID, UserResource(view, false)); err != nil {
			return err
		}
		return store.DeleteRevokingGrant(ctx, w.store.Pool, job.UserID, job.AppID)
	}

	// Locked or removed in Asgardeo: kept, but inactive, in the application.
	active := !view.User.Locked && view.User.RemovedAt == nil
	id, err := w.scim.upsert(ctx, view.App.SCIMURL, token, remoteID, UserResource(view, active))
	if err != nil {
		return err
	}
	return store.MarkGrantProvisioned(ctx, w.store.Pool, job.UserID, job.AppID, id, time.Now())
}
