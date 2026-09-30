package web

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// logRequests logs every API and sign-in request (not the dashboard's
// static files), and turns a panic into a 500 instead of a dropped
// connection.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic serving request", "method", r.Method, "path", r.URL.Path,
					"panic", p, "stack", string(debug.Stack()))
				if rec.status == 0 {
					writeError(rec, http.StatusInternalServerError, "INTERNAL", "Something went wrong. It has been logged.")
				}
			}
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			if isStaticAsset(r.URL.Path) && rec.status < 400 {
				return
			}
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			}
			s.log.Log(r.Context(), level, "request", "method", r.Method, "path", r.URL.Path,
				"status", rec.status, "duration", time.Since(start).Round(time.Millisecond))
		}()
		next.ServeHTTP(rec, r)
	})
}

func isStaticAsset(path string) bool {
	return len(path) > 8 && path[:8] == "/assets/" || path == "/favicon.png" || path == "/logo.png" || path == "/mark.png" || path == "/auth/page.css" || path == "/healthz"
}
