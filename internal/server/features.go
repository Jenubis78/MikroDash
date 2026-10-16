package server

import (
	"net/http"

	"mikrodash/internal/store"
)

// featureOn reports whether an optional feature is switched on. Read from the
// file on every call, as every setting is, so a save in Settings applies to the
// next request without a restart. A file that cannot be read is a feature that
// is off.
func (s *Server) featureOn(key string) bool {
	merged, err := s.mergedSettings()
	return err == nil && store.FeatureOn(merged, key)
}

// featureGate refuses a request for a feature that is off. The page draws no
// control for it then, so arriving here is a stale page or a hand-built
// request, and 403 is the honest answer to both.
func (s *Server) featureGate(w http.ResponseWriter, key string) bool {
	if s.featureOn(key) {
		return true
	}
	writeJSONErr(w, http.StatusForbidden, "this feature is switched off in Settings -> Features")
	return false
}
