package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheClientHistoryChoiceFollowsItsGates. Asking whether a router is recorded
// and switching it need the feature, a signed-in user and the Wifi Clients page
// on that router, before anything is read or written.
func TestTheClientHistoryChoiceFollowsItsGates(t *testing.T) {
	for _, c := range []struct {
		name, settings, method, url, body string
		signedIn                          bool
		want                              int
	}{
		{"status, signed out", `{"wifiHistoryEnabled":true}`, "GET", "/api/wifi/history/status?routerId=r-A", "", false, 401},
		{"status, switched off", `{}`, "GET", "/api/wifi/history/status?routerId=r-A", "", true, 403},
		{"status, bad router id", `{"wifiHistoryEnabled":true}`, "GET", "/api/wifi/history/status?routerId=../x", "", true, 400},
		{"status, no Wifi Clients grant", `{"wifiHistoryEnabled":true}`, "GET", "/api/wifi/history/status?routerId=r-A", "", true, 403},
		{"record, signed out", `{"wifiHistoryEnabled":true}`, "POST", "/api/wifi/history/record", `{"routerId":"r-A","on":true}`, false, 401},
		{"record, switched off", `{}`, "POST", "/api/wifi/history/record", `{"routerId":"r-A","on":true}`, true, 403},
		{"record, no Wifi Clients grant", `{"wifiHistoryEnabled":true}`, "POST", "/api/wifi/history/record", `{"routerId":"r-A","on":true}`, true, 403},
	} {
		s := gateServer(t, c.settings, "")
		req := httptest.NewRequest(c.method, c.url, strings.NewReader(c.body))
		if c.signedIn {
			req.Header.Set("Cookie", authed)
		}
		w := httptest.NewRecorder()
		h := s.wifiHistoryStatus
		if c.method == "POST" {
			h = s.wifiHistoryRecord
		}
		h(w, req)
		if w.Code != c.want {
			t.Errorf("%s: answered %d (%s), want %d", c.name, w.Code, strings.TrimSpace(w.Body.String()), c.want)
		}
		if c.want == 403 {
			if on, _ := s.auditDB.WifiHistoryRouters(); len(on) != 0 {
				t.Errorf("%s: a refused request switched recording on: %v", c.name, on)
			}
		}
	}
}
