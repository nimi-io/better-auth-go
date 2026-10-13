package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/captcha"
)

// Captcha profile (mirrors e2e/servers/profiles/captcha.mjs): Cloudflare Turnstile with
// the siteverify API answered in-process. The token "valid-token" passes, "wrong-host"
// passes with another hostname, anything else fails. /__test/captcha returns the last
// siteverify request.
func init() {
	var mu sync.Mutex
	var last map[string]string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		last = map[string]string{"url": r.URL.String(), "contentType": r.Header.Get("Content-Type"), "body": string(raw)}
		mu.Unlock()
		var in struct{ Response string }
		_ = json.Unmarshal(raw, &in)
		data := `{"success":false,"error-codes":["invalid-input-response"]}`
		switch in.Response {
		case "valid-token":
			data = `{"success":true,"hostname":"app.example.com","action":"login"}`
		case "wrong-host":
			data = `{"success":true,"hostname":"evil.example.com","action":"login"}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(data)), Request: r}, nil
	})
	profiles["captcha"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Database = pluginSQLite()
		cfg.Plugins = append(cfg.Plugins, captcha.New(captcha.Options{
			Provider: captcha.CloudflareTurnstile, SecretKey: "turnstile-secret",
			AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "login",
			HTTPClient: &http.Client{Transport: transport},
		}))
	}
	testHandlers["/__test/captcha"] = func(w http.ResponseWriter, _ *http.Request, _ *betterauth.Auth) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(last)
	}
}
