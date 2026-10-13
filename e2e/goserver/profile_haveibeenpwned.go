package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/haveibeenpwned"
)

// Have I Been Pwned profile (mirrors e2e/servers/profiles/haveibeenpwned.mjs). The range
// API is answered in-process: "password123" and "breached-password" are breached.
// /__test/pwned returns the last outbound request.
func init() {
	var mu sync.Mutex
	var last map[string]string
	breached := []string{"password123", "breached-password"}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		prefix := strings.TrimPrefix(r.URL.String(), haveibeenpwned.RangeURL)
		mu.Lock()
		last = map[string]string{"url": r.URL.String(), "addPadding": r.Header.Get("Add-Padding"), "userAgent": r.Header.Get("User-Agent")}
		mu.Unlock()
		var b strings.Builder
		for _, pw := range breached {
			s := sha1.Sum([]byte(pw))
			h := strings.ToUpper(hex.EncodeToString(s[:]))
			if strings.HasPrefix(h, prefix) {
				b.WriteString(h[5:] + ":5\r\n")
			}
		}
		b.WriteString("0000000000000000000000000000000000A:0")
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(b.String())), Request: r}, nil
	})
	profiles["haveibeenpwned"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Database = pluginSQLite()
		cfg.Plugins = append(cfg.Plugins, haveibeenpwned.New(haveibeenpwned.Options{HTTPClient: &http.Client{Transport: transport}}))
	}
	testHandlers["/__test/pwned"] = func(w http.ResponseWriter, _ *http.Request, _ *betterauth.Auth) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(last)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
