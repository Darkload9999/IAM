package web

// The Asgardeo console through the Hub (hub/console.go).

import (
	"net/http"

	"github.com/zeit26/identity-hub/internal/hub"
)

func (s *Server) apiCapabilities(w http.ResponseWriter, r *http.Request, p *principal) error {
	caps, err := s.svc.Capabilities(r.Context(), r.URL.Query().Get("refresh") == "1")
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": caps})
	return nil
}

// ---------------------------------------------------------------- groups

func (s *Server) apiListGroups(w http.ResponseWriter, r *http.Request, p *principal) error {
	groups, err := s.svc.ListGroups(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
	return nil
}

func (s *Server) apiGetGroupDetail(w http.ResponseWriter, r *http.Request, p *principal) error {
	group, err := s.svc.GetGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": group})
	return nil
}

func (s *Server) apiCreateConsoleGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	group, err := s.svc.CreateConsoleGroup(r.Context(), actor(p), in.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"group": group})
	return nil
}

func (s *Server) apiRenameGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	group, err := s.svc.RenameConsoleGroup(r.Context(), actor(p), r.PathValue("id"), in.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": group})
	return nil
}

func (s *Server) apiDeleteConsoleGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.DeleteConsoleGroup(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) apiGroupMember(member bool) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		group, err := s.svc.SetGroupMember(r.Context(), actor(p), r.PathValue("id"), r.PathValue("userId"), member)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"group": group})
		return nil
	}
}

// ----------------------------------------------------------------- roles

func (s *Server) apiListConsoleRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	roles, err := s.svc.ListConsoleRoles(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
	return nil
}

func (s *Server) apiGetConsoleRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	role, err := s.svc.GetConsoleRole(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": role})
	return nil
}

func (s *Server) apiCreateConsoleRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	role, err := s.svc.CreateConsoleRole(r.Context(), actor(p), in.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"role": role})
	return nil
}

func (s *Server) apiDeleteConsoleRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.DeleteConsoleRole(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) apiRoleMember(assigned bool) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		role, err := s.svc.SetRoleMember(r.Context(), actor(p), r.PathValue("id"),
			r.PathValue("kind"), r.PathValue("memberId"), assigned)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"role": role})
		return nil
	}
}

// ---------------------------------------------------------- applications

func (s *Server) apiListConsoleApps(w http.ResponseWriter, r *http.Request, p *principal) error {
	apps, err := s.svc.ListConsoleApps(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"applications": apps})
	return nil
}

func (s *Server) apiGetConsoleApp(w http.ResponseWriter, r *http.Request, p *principal) error {
	app, err := s.svc.GetConsoleApp(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"application": app})
	return nil
}

// ------------------------------------------------------ sessions & reset

func (s *Server) apiListSessions(w http.ResponseWriter, r *http.Request, p *principal) error {
	sessions, err := s.svc.ListSessions(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
	return nil
}

func (s *Server) apiEndSessions(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.svc.TerminateSessions(r.Context(), actor(p), r.PathValue("id"), r.PathValue("sid")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) apiResetPassword(w http.ResponseWriter, r *http.Request, p *principal) error {
	if r.PathValue("id") == p.User.ID {
		return &hub.Error{Status: http.StatusConflict, Code: "PROTECTED",
			Message: "Change your own password from Asgardeo's My Account"}
	}
	if err := s.svc.ResetPassword(r.Context(), actor(p), r.PathValue("id")); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// -------------------------------------------------------------- policies

func (s *Server) apiListPolicies(w http.ResponseWriter, r *http.Request, p *principal) error {
	policies, err := s.svc.ListPolicies(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
	return nil
}

func (s *Server) apiUpdatePolicy(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Values map[string]string `json:"values"`
	}
	if err := readJSON(r, &in); err != nil {
		return err
	}
	policy, err := s.svc.UpdatePolicy(r.Context(), actor(p), r.PathValue("category"), r.PathValue("id"), in.Values)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy})
	return nil
}
