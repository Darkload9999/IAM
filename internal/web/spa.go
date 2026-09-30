package web

import (
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// dashboard serves the built React app: its files as they are, and
// index.html for every other page (the app routes in the browser). Pages
// need a signed-in admin; the files themselves hold nothing secret.
func (s *Server) dashboard() http.Handler {
	ui := s.opts.UI
	if ui != nil {
		if _, err := fs.Stat(ui, "index.html"); err != nil {
			ui = nil
		}
	}
	var files http.Handler
	if ui != nil {
		files = http.FileServerFS(ui)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if ui != nil && name != "" && name != "index.html" {
			if info, err := fs.Stat(ui, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// Vite puts a content hash in every asset's name.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					// The logo and icons keep their names across builds.
					w.Header().Set("Cache-Control", "no-cache")
				}
				files.ServeHTTP(w, r)
				return
			}
		}

		_, status := s.authenticate(r)
		switch status {
		case http.StatusOK:
		case http.StatusUnauthorized:
			http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		case http.StatusForbidden:
			s.page(w, http.StatusForbidden, "No access to the Identity Hub",
				"Your account is no longer a Hub admin.", "/auth/login", "Sign in as someone else")
			return
		default:
			s.page(w, http.StatusInternalServerError, "Something went wrong", "It has been logged. Try again.", "/", "Reload")
			return
		}

		if ui == nil {
			s.page(w, http.StatusOK, "Dashboard not built",
				"The API is running, but the dashboard was not built into this binary. Run make build.", "", "")
			return
		}
		index, err := fs.ReadFile(ui, "index.html")
		if err != nil {
			s.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(index)
	})
}
