// Package oauth2test provides an in-process fake for provider HTTP APIs: requests made
// through oauth2.HTTPClient to real provider URLs (https://github.com/..., ...) are routed
// to handlers registered in the test, and an RSA key can sign id tokens served via JWKS.
package oauth2test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Request is a recorded outbound request.
type Request struct {
	Method string
	URL    *url.URL
	Header http.Header
	Form   url.Values
	Body   string
}

// Server intercepts outbound provider requests.
type Server struct {
	mu       sync.Mutex
	routes   map[string]http.HandlerFunc
	Requests []Request
	Key      *rsa.PrivateKey
	KeyID    string
}

type transport struct{ s *Server }

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		r.Body = io.NopCloser(strings.NewReader(body))
	}
	form, _ := url.ParseQuery(body)
	t.s.mu.Lock()
	t.s.Requests = append(t.s.Requests, Request{Method: r.Method, URL: r.URL, Header: r.Header.Clone(), Form: form, Body: body})
	h := t.s.routes[r.Method+" "+r.URL.Host+r.URL.Path]
	if h == nil {
		h = t.s.routes[r.URL.Host+r.URL.Path]
	}
	t.s.mu.Unlock()
	rec := httptest.NewRecorder()
	if h == nil {
		rec.WriteHeader(404)
		_, _ = rec.WriteString(`{"error":"not_found","path":"` + r.URL.String() + `"}`)
	} else {
		h(rec, r)
	}
	return rec.Result(), nil
}

// New installs the fake as oauth2.HTTPClient's transport for the duration of the test.
func New(t testing.TB) *Server {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{routes: map[string]http.HandlerFunc{}, Key: key, KeyID: "test-key"}
	prev := oauth2.HTTPClient.Transport
	oauth2.HTTPClient.Transport = transport{s}
	oauth2.ResetJWKSCache()
	t.Cleanup(func() {
		oauth2.HTTPClient.Transport = prev
		oauth2.ResetJWKSCache()
	})
	return s
}

// Handle registers a handler for "host/path" or "METHOD host/path"
// (e.g. "github.com/login/oauth/access_token", "GET api.github.com/user").
func (s *Server) Handle(pattern string, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[pattern] = h
}

// JSON registers a handler answering with a fixed JSON body.
func (s *Server) JSON(pattern string, status int, body any) {
	s.Handle(pattern, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
}

// JWKS returns the public key set for Key.
func (s *Server) JWKS() jose.JWKS {
	j, _ := jose.JWKFromPublicKey(&s.Key.PublicKey)
	j.Kid, j.Alg, j.Use = s.KeyID, "RS256", "sig"
	return jose.JWKS{Keys: []jose.JWK{j}}
}

// ServeJWKS registers the JWKS at pattern.
func (s *Server) ServeJWKS(pattern string) { s.JSON(pattern, 200, s.JWKS()) }

// IDToken signs claims with Key (RS256). iat/exp default to now / now+1h.
func (s *Server) IDToken(claims map[string]any) string {
	p := jsonx.NewObject()
	if _, ok := claims["iat"]; !ok {
		p.Set("iat", float64(time.Now().Unix()))
	}
	if _, ok := claims["exp"]; !ok {
		p.Set("exp", float64(time.Now().Add(time.Hour).Unix()))
	}
	for k, v := range claims {
		p.Set(k, v)
	}
	tok, err := jose.SignJWT(jsonx.O("alg", "RS256", "kid", s.KeyID, "typ", "JWT"), p, s.Key)
	if err != nil {
		panic(err)
	}
	return tok
}

// Last returns the last recorded request to host/path (nil when none).
func (s *Server) Last(hostPath string) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.Requests) - 1; i >= 0; i-- {
		if s.Requests[i].URL.Host+s.Requests[i].URL.Path == hostPath {
			r := s.Requests[i]
			return &r
		}
	}
	return nil
}
