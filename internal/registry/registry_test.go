package registry

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestImageNamesParse(t *testing.T) {
	for in, want := range map[string]Ref{
		"ghcr.io/jenubis78/mikrodash-dpi:latest": {"ghcr.io", "jenubis78/mikrodash-dpi", "latest"},
		"ghcr.io/jenubis78/mikrodash-dpi":        {"ghcr.io", "jenubis78/mikrodash-dpi", "latest"},
		"ghcr.io/jenubis78/mikrodash-dpi:0.2.0":  {"ghcr.io", "jenubis78/mikrodash-dpi", "0.2.0"},
		"alpine:3.24":                            {"registry-1.docker.io", "library/alpine", "3.24"},
		"docker.io/someone/thing:1":              {"registry-1.docker.io", "someone/thing", "1"},
		"localhost:5000/x:2":                     {"localhost:5000", "x", "2"},
	} {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ghcr.io/x@sha256:abc"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	r, _ := Parse("ghcr.io/jenubis78/mikrodash-dpi:latest")
	if r.WithTag("0.3.0") != "ghcr.io/jenubis78/mikrodash-dpi:0.3.0" {
		t.Error(r.WithTag("0.3.0"))
	}
}

func TestABearerChallengeReads(t *testing.T) {
	got := Challenge(`Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull"`)
	want := map[string]string{"realm": "https://ghcr.io/token", "service": "ghcr.io", "scope": "repository:a/b:pull"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v", got)
	}
}

// The registry's dance, played by a test server: 401 with a challenge, an
// anonymous token, then the tags with it.
func TestTagsAnswersTheChallengeAnonymously(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:jenubis78/mikrodash-dpi:pull" || r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token":"t0k"}`))
		case r.Header.Get("Authorization") != "Bearer t0k":
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+r.Host+`/token",service="x",scope="repository:jenubis78/mikrodash-dpi:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte(`{"name":"jenubis78/mikrodash-dpi","tags":["0.1.0","0.2.0","latest"]}`))
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, host)
		}}}
	tags, err := Tags(context.Background(), c, Ref{Host: host, Repo: "jenubis78/mikrodash-dpi", Tag: "latest"})
	if err != nil || !reflect.DeepEqual(tags, []string{"0.1.0", "0.2.0", "latest"}) {
		t.Fatalf("%v %v", err, tags)
	}
}
