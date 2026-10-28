// Package registry asks a container registry which tags an image has, over
// the OCI distribution API with net/http: enough for the IPS page to offer a
// sensor update when its registry holds a newer release.
//
// ── ANONYMOUS, THE WAY A PULL IS ────────────────────────────────────────────
//
// A public image's tags are readable by anyone: the registry answers 401 with
// a Bearer challenge naming where to get a pull token, the token comes back
// without credentials, and the request is made again with it. GHCR and Docker
// Hub both work this way. A private image is not something this asks about.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Ref is an image reference: registry host, repository, tag.
type Ref struct {
	Host string
	Repo string
	Tag  string
}

// Parse reads "ghcr.io/owner/name:tag" (or a Docker Hub short name, where
// "name" is library/name and the host is Docker Hub's). A digest pin is not
// a tag and is refused.
func Parse(image string) (Ref, error) {
	image = strings.TrimSpace(image)
	if image == "" || strings.Contains(image, "@") {
		return Ref{}, fmt.Errorf("%q is not an image name with a tag", image)
	}
	r := Ref{Tag: "latest"}
	name := image
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, r.Tag = name[:i], name[i+1:]
	}
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		r.Host, r.Repo = parts[0], parts[1]
	} else {
		r.Host, r.Repo = "registry-1.docker.io", name
		if !strings.Contains(name, "/") {
			r.Repo = "library/" + name
		}
	}
	if r.Host == "docker.io" {
		r.Host = "registry-1.docker.io"
	}
	if r.Repo == "" || r.Tag == "" {
		return Ref{}, fmt.Errorf("%q is not an image name with a tag", image)
	}
	return r, nil
}

// WithTag is the reference with another tag, as an image name.
func (r Ref) WithTag(tag string) string {
	host := r.Host
	if host == "registry-1.docker.io" {
		host = "docker.io"
	}
	return host + "/" + r.Repo + ":" + tag
}

// Tags lists the image's tags.
func Tags(ctx context.Context, c *http.Client, r Ref) ([]string, error) {
	u := "https://" + r.Host + "/v2/" + r.Repo + "/tags/list?n=1000"
	res, err := get(ctx, c, u, "")
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		challenge := res.Header.Get("WWW-Authenticate")
		res.Body.Close()
		tok, err := token(ctx, c, challenge)
		if err != nil {
			return nil, err
		}
		if res, err = get(ctx, c, u, tok); err != nil {
			return nil, err
		}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the registry answered %s for %s", res.Status, r.Repo)
	}
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.Tags, nil
}

func get(ctx context.Context, c *http.Client, u, bearer string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.Do(req)
}

// token answers a Bearer challenge anonymously.
func token(ctx context.Context, c *http.Client, challenge string) (string, error) {
	params := Challenge(challenge)
	realm := params["realm"]
	ru, err := url.Parse(realm)
	if err != nil || ru.Scheme != "https" {
		return "", errors.New("the registry asked for credentials in a way this cannot answer")
	}
	q := ru.Query()
	for _, k := range []string{"service", "scope"} {
		if v := params[k]; v != "" {
			q.Set(k, v)
		}
	}
	ru.RawQuery = q.Encode()
	res, err := get(ctx, c, ru.String(), "")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the registry's token service answered %s", res.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	return body.AccessToken, nil
}

// Challenge reads `Bearer realm="…",service="…",scope="…"`.
func Challenge(h string) map[string]string {
	out := map[string]string{}
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return out
	}
	rest := h[len("bearer "):]
	for len(rest) > 0 {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(rest[:eq])
		rest = rest[eq+1:]
		var val string
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				break
			}
			val, rest = rest[1:1+end], rest[2+end:]
		} else if i := strings.IndexByte(rest, ','); i >= 0 {
			val, rest = rest[:i], rest[i:]
		} else {
			val, rest = rest, ""
		}
		out[strings.ToLower(key)] = val
		rest = strings.TrimLeft(rest, ", ")
	}
	return out
}
