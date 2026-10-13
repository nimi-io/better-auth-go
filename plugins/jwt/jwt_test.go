package jwt_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	_ "modernc.org/sqlite"
)

func withJWT(o jwt.Options) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Plugins = append(c.Plugins, jwt.New(o)) }
}

func fetchJWKS(t *testing.T, in *instance, path string) jose.JWKS {
	t.Helper()
	res := in.do("GET", path, nil, nil)
	if res.Status != 200 {
		t.Fatalf("jwks: %d %s", res.Status, res.Body)
	}
	set, err := jose.ParseJWKS(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func fetchToken(t *testing.T, in *instance, headers map[string][]string) string {
	t.Helper()
	res := in.do("GET", "/token", nil, headers)
	if res.Status != 200 {
		t.Fatalf("token: %d %s", res.Status, res.Body)
	}
	tok, _ := res.json(t)["token"].(string)
	if tok == "" {
		t.Fatalf("no token: %s", res.Body)
	}
	return tok
}

// verifyLocal is jwtVerify(token, createLocalJWKSet(jwks)).
func verifyLocal(t *testing.T, token string, set jose.JWKS) *jsonx.Object {
	t.Helper()
	_, payload, err := jose.VerifyJWT(token, jose.KeySetFunc(set), jose.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return payload
}

func TestJWT(t *testing.T) {
	in := newInstance(t, withJWT(jwt.Options{}))
	headers := in.signInWithTestUser()

	t.Run("Client gets a token from session", func(t *testing.T) {
		res := in.do("GET", "/get-session", nil, headers)
		if tok := res.Header.Get("set-auth-jwt"); len(tok) <= 10 {
			t.Fatalf("expected set-auth-jwt, got %q (%v)", tok, res.Header)
		}
		if !strings.Contains(res.Header.Get("Access-Control-Expose-Headers"), "set-auth-jwt") {
			t.Fatalf("expose headers: %q", res.Header.Get("Access-Control-Expose-Headers"))
		}
	})
	t.Run("Client gets a token", func(t *testing.T) {
		fetchToken(t, in, headers)
	})
	t.Run("Get JWKS", func(t *testing.T) {
		fetchToken(t, in, headers)
		set := fetchJWKS(t, in, "/jwks")
		if len(set.Keys) == 0 || set.Keys[0].Alg != "EdDSA" {
			t.Fatalf("unexpected jwks %+v", set)
		}
	})
	t.Run("Signed tokens can be validated with the JWKS", func(t *testing.T) {
		tok := fetchToken(t, in, headers)
		verifyLocal(t, tok, fetchJWKS(t, in, "/jwks"))
	})
	t.Run("should set subject to user id by default", func(t *testing.T) {
		tok := fetchToken(t, in, headers)
		p := verifyLocal(t, tok, fetchJWKS(t, in, "/jwks"))
		sub, _ := p.Get("sub")
		id, _ := p.Get("id")
		if sub == nil || sub != id {
			t.Fatalf("sub %v id %v", sub, id)
		}
	})

	type outcome struct {
		ec     string
		length int
		crv    string
		alg    string
	}
	algorithms := []struct {
		cfg jwt.JWKOptions
		out outcome
	}{
		{jwt.JWKOptions{Alg: "EdDSA", Crv: "Ed25519"}, outcome{"OKP", 43, "Ed25519", "EdDSA"}},
		{jwt.JWKOptions{Alg: "ES256"}, outcome{"EC", 43, "P-256", "ES256"}},
		{jwt.JWKOptions{Alg: "ES512"}, outcome{"EC", 88, "P-521", "ES512"}},
		{jwt.JWKOptions{Alg: "PS256"}, outcome{"RSA", 342, "", "PS256"}},
		{jwt.JWKOptions{Alg: "RS256"}, outcome{"RSA", 342, "", "RS256"}},
	}
	for _, algo := range algorithms {
		for _, disable := range []bool{false, true} {
			cfg := algo.cfg
			opts := jwt.Options{JWKS: &jwt.JWKSOptions{KeyPairConfig: &cfg, DisablePrivateKeyEncryption: disable}}
			alg := cfg.Alg
			if cfg.Crv != "" {
				alg += "(" + cfg.Crv + ")"
			}
			enc := ""
			if disable {
				enc = " without private key encryption"
			}
			exp := algo.out
			inst := newInstance(t, withJWT(opts))
			checkLen := func(t *testing.T, name, v string) {
				if v != "" && len(v) != exp.length {
					t.Fatalf("%s length %d, want %d", name, len(v), exp.length)
				}
			}
			t.Run(alg+" algorithm"+enc+" can be used to generate JWKS", func(t *testing.T) {
				kp, err := jwt.GenerateExportedKeyPair(&opts)
				if err != nil {
					t.Fatal(err)
				}
				for _, k := range []jose.JWK{kp.PublicWebKey, kp.PrivateWebKey} {
					if k.Kty != exp.ec {
						t.Fatalf("kty %s", k.Kty)
					}
					checkLen(t, "x", k.X)
					checkLen(t, "y", k.Y)
					checkLen(t, "n", k.N)
				}
				res, err := inst.call("getJwks", betterauth.CallInput{})
				if err != nil {
					t.Fatal(err)
				}
				var set jose.JWKS
				if err := res.Decode(&set); err != nil {
					t.Fatal(err)
				}
				k := set.Keys[0]
				if k.Kty != exp.ec || k.Alg != exp.alg {
					t.Fatalf("key %+v", k)
				}
				if k.Crv != "" && k.Crv != exp.crv {
					t.Fatalf("crv %s", k.Crv)
				}
				checkLen(t, "x", k.X)
				checkLen(t, "y", k.Y)
				checkLen(t, "n", k.N)
			})
			var h map[string][]string
			t.Run(alg+" algorithm"+enc+": Client can sign in", func(t *testing.T) {
				h = inst.signInWithTestUser()
			})
			t.Run(alg+" algorithm"+enc+": Client gets a token", func(t *testing.T) {
				fetchToken(t, inst, h)
			})
			t.Run(alg+" algorithm"+enc+": Client gets a token from session", func(t *testing.T) {
				res := inst.do("GET", "/get-session", nil, h)
				if len(res.Header.Get("set-auth-jwt")) <= 10 {
					t.Fatal("missing set-auth-jwt")
				}
			})
			t.Run(alg+" algorithm"+enc+": Signed tokens can be validated with the JWKS", func(t *testing.T) {
				verifyLocal(t, fetchToken(t, inst, h), fetchJWKS(t, inst, "/jwks"))
			})
			t.Run(alg+" algorithm"+enc+": Should set subject to user id by default", func(t *testing.T) {
				p := verifyLocal(t, fetchToken(t, inst, h), fetchJWKS(t, inst, "/jwks"))
				sub, _ := p.Get("sub")
				id, _ := p.Get("id")
				if sub == nil || sub != id {
					t.Fatalf("sub %v id %v", sub, id)
				}
			})
		}
	}
}

func TestSignJWTAlg(t *testing.T) {
	for _, cfg := range []jwt.JWKOptions{{Alg: "EdDSA", Crv: "Ed25519"}, {Alg: "ES256"}, {Alg: "ES512"}, {Alg: "PS256"}, {Alg: "RS256"}} {
		cfg := cfg
		t.Run("signJWT - alg: "+cfg.Alg, func(t *testing.T) {
			in := newInstance(t, withJWT(jwt.Options{JWKS: &jwt.JWKSOptions{KeyPairConfig: &cfg}}))
			t.Run("should sign a JWT", func(t *testing.T) {
				res, err := in.call("signJWT", betterauth.CallInput{Body: map[string]any{"payload": map[string]any{
					"sub": "123", "exp": 1000, "iat": 1000, "iss": "https://example.com", "aud": "https://example.com", "custom": "custom",
				}}})
				if err != nil {
					t.Fatal(err)
				}
				var out struct{ Token string }
				_ = res.Decode(&out)
				if out.Token == "" {
					t.Fatal("no token")
				}
			})
			t.Run("should be a valid JWT", func(t *testing.T) {
				now := time.Now().Unix()
				res, err := in.call("signJWT", betterauth.CallInput{Body: map[string]any{"payload": map[string]any{
					"sub": "123", "exp": now + 600, "iat": now, "iss": "https://example.com", "aud": "https://example.com", "custom": "custom",
				}}})
				if err != nil {
					t.Fatal(err)
				}
				var out struct{ Token string }
				_ = res.Decode(&out)
				jr, err := in.call("getJwks", betterauth.CallInput{})
				if err != nil {
					t.Fatal(err)
				}
				var set jose.JWKS
				_ = jr.Decode(&set)
				header, payload, err := jose.VerifyJWT(out.Token, jose.KeySetFunc(set), jose.VerifyOptions{})
				if err != nil {
					t.Fatal(err)
				}
				kid, _ := header.Get("kid")
				found := false
				for _, k := range set.Keys {
					if k.Kid == kid {
						found = true
					}
				}
				if !found {
					t.Fatal("kid not in jwks")
				}
				for k, want := range map[string]any{"iss": "https://example.com", "aud": "https://example.com", "sub": "123", "custom": "custom"} {
					if v, _ := payload.Get(k); v != want {
						t.Fatalf("%s = %v", k, v)
					}
				}
				for _, k := range []string{"exp", "iat"} {
					if v, _ := payload.Get(k); v == nil {
						t.Fatalf("missing %s", k)
					}
				}
				if alg, _ := header.Get("alg"); alg != cfg.Alg {
					t.Fatalf("alg %v", alg)
				}
			})
			t.Run("shouldn't let you sign from a client", func(t *testing.T) {
				res := in.do("POST", "/sign-jwt", map[string]any{"payload": map[string]any{"sub": "123"}}, nil)
				if res.Status != 404 {
					t.Fatalf("status %d", res.Status)
				}
			})
		})
	}
}

func newErr(t *testing.T, o jwt.Options) error {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	_, err := betterauth.New(betterauth.Config{BaseURL: "http://localhost:3000", Secret: testSecret, Logger: betterauth.NopLogger{},
		Plugins: []*betterauth.Plugin{jwt.New(o)}})
	return err
}

func TestJWTRemoteSigning(t *testing.T) {
	t.Run("should fail if sign is defined and remoteUrl is not", func(t *testing.T) {
		err := newErr(t, jwt.Options{JWT: &jwt.JWTOptions{Sign: func(*betterauth.EndpointContext, *jsonx.Object, *jwt.Header, jwt.SigningConfig) (string, error) {
			return "123", nil
		}}})
		if err == nil || !strings.Contains(err.Error(), "options.jwks.remoteUrl must be set when using options.jwt.sign") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestJWTRemoteURL(t *testing.T) {
	remote := func(alg, url string) jwt.Options {
		return jwt.Options{JWKS: &jwt.JWKSOptions{RemoteURL: url, KeyPairConfig: &jwt.JWKOptions{Alg: alg}}}
	}
	t.Run("should require specifying the alg when using remoteUrl", func(t *testing.T) {
		err := newErr(t, jwt.Options{JWKS: &jwt.JWKSOptions{RemoteURL: "https://example.com/.well-known/jwks.json"}})
		if err == nil || !strings.Contains(err.Error(), "options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("should accept remoteUrl with alg specified", func(t *testing.T) {
		newInstance(t, withJWT(remote("ES256", "https://example.com/.well-known/jwks.json")))
	})
	t.Run("should disable /jwks endpoint when remoteUrl is configured", func(t *testing.T) {
		in := newInstance(t, withJWT(remote("ES256", "https://example.com/.well-known/jwks.json")))
		if res := in.do("GET", "/jwks", nil, nil); res.Status != 404 {
			t.Fatalf("status %d", res.Status)
		}
	})
	t.Run("should work with different algorithms when remoteUrl is set", func(t *testing.T) {
		for _, alg := range []string{"ES256", "ES512", "RS256", "PS256", "EdDSA"} {
			newInstance(t, withJWT(remote(alg, "https://example.com/.well-known/jwks.json")))
		}
	})
	t.Run("should still allow token generation when remoteUrl is set", func(t *testing.T) {
		in := newInstance(t, withJWT(remote("ES256", "https://example.com/.well-known/jwks.json")))
		tok := fetchToken(t, in, in.signInWithTestUser())
		if len(strings.Split(tok, ".")) != 3 {
			t.Fatalf("not a JWT: %s", tok)
		}
	})
	t.Run("should work with custom sign function and remoteUrl", func(t *testing.T) {
		o := remote("ES256", "https://example.com/.well-known/jwks.json")
		o.JWT = &jwt.JWTOptions{Sign: func(_ *betterauth.EndpointContext, payload *jsonx.Object, _ *jwt.Header, _ jwt.SigningConfig) (string, error) {
			h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
			b := base64.RawURLEncoding.EncodeToString(jsonx.MustMarshal(payload))
			return h + "." + b + ".mock-signature", nil
		}}
		in := newInstance(t, withJWT(o))
		tok := fetchToken(t, in, in.signInWithTestUser())
		if !strings.Contains(tok, "mock-signature") {
			t.Fatalf("token %s", tok)
		}
	})
	t.Run("should validate that remoteUrl is a valid URL format", func(t *testing.T) {
		for _, u := range []string{"not-a-url", "http://", "//example.com", "example.com/jwks"} {
			newInstance(t, withJWT(remote("ES256", u)))
		}
	})
	t.Run("should work with remoteUrl pointing to different paths", func(t *testing.T) {
		for _, u := range []string{"https://example.com/.well-known/jwks.json", "https://auth.example.com/jwks", "https://api.example.com/v1/keys", "https://example.com:8080/jwks.json"} {
			newInstance(t, withJWT(remote("ES256", u)))
		}
	})
	t.Run("should handle remoteUrl with query parameters", func(t *testing.T) {
		newInstance(t, withJWT(remote("RS256", "https://example.com/jwks?version=1&format=json")))
	})
	t.Run("should not interfere with other JWT endpoints when remoteUrl is set", func(t *testing.T) {
		in := newInstance(t, withJWT(remote("ES256", "https://example.com/.well-known/jwks.json")))
		h := in.signInWithTestUser()
		fetchToken(t, in, h)
		if res := in.do("GET", "/jwks", nil, nil); res.Status != 404 {
			t.Fatalf("jwks status %d", res.Status)
		}
		if res := in.do("GET", "/get-session", nil, h); res.Header.Get("set-auth-jwt") == "" {
			t.Fatal("missing set-auth-jwt")
		}
	})
}

func TestJWTCustomAdapter(t *testing.T) {
	t.Run("should use custom adapter", func(t *testing.T) {
		var storage []*jwt.Jwk
		in := newInstance(t, withJWT(jwt.Options{Adapter: &jwt.AdapterOptions{
			GetJwks: func(*betterauth.EndpointContext) ([]*jwt.Jwk, error) { return storage, nil },
			CreateJwk: func(_ *betterauth.EndpointContext, data jwt.Jwk) (*jwt.Jwk, error) {
				data.ID = crypto.RandomUUID()
				data.CreatedAt = time.Now()
				storage = append(storage, &data)
				return &data, nil
			},
		}}))
		res, err := in.call("signJWT", betterauth.CallInput{Body: map[string]any{"payload": map[string]any{"sub": "123"}}})
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Token string }
		_ = res.Decode(&out)
		if out.Token == "" || len(storage) != 1 {
			t.Fatalf("token %q storage %d", out.Token, len(storage))
		}
	})
}

func TestJWTCustomJWKSPath(t *testing.T) {
	t.Run("should use custom jwksPath when specified", func(t *testing.T) {
		in := newInstance(t, withJWT(jwt.Options{JWKS: &jwt.JWKSOptions{JWKSPath: "/.well-known/jwks.json"}}))
		set := fetchJWKS(t, in, "/.well-known/jwks.json")
		if len(set.Keys) == 0 {
			t.Fatal("no keys")
		}
		if res := in.do("GET", "/jwks", nil, nil); res.Status != 404 {
			t.Fatalf("old path status %d", res.Status)
		}
	})
	t.Run("rejects invalid jwksPath", func(t *testing.T) {
		for _, p := range []string{"jwks", "/../jwks"} {
			err := newErr(t, jwt.Options{JWKS: &jwt.JWKSOptions{JWKSPath: p}})
			if err == nil || !strings.Contains(err.Error(), "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'") {
				t.Fatalf("%s: %v", p, err)
			}
		}
	})
}

func TestJWTMintingInsideTransaction(t *testing.T) {
	t.Run("mints the first signing key through the transaction-scoped adapter instead of deadlocking on the connection", func(t *testing.T) {
		t.Setenv("NODE_ENV", "test")
		conn, err := sql.Open("sqlite", "file::memory:?_pragma=foreign_keys(1)")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = conn.Close() })
		a, err := betterauth.New(betterauth.Config{
			BaseURL: "http://localhost:3000", Secret: "better-auth.secret", Logger: betterauth.NopLogger{},
			Database:         sqladapter.New(conn, sqladapter.Config{}),
			EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
			Plugins:          []*betterauth.Plugin{jwt.New()},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.RunMigrations(context.Background()); err != nil {
			t.Fatal(err)
		}
		res, err := a.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: "transactional-jwks@example.com", Password: "password123", Name: "Transactional JWKS User"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h := map[string][]string{"Cookie": {strings.SplitN(res.Headers.Values("Set-Cookie")[0], ";", 2)[0]}}
		done := make(chan error, 1)
		var token string
		go func() {
			done <- a.Context().RunWithTransaction(context.Background(), func(ctx context.Context) error {
				r, err := a.API.Call(ctx, "getToken", betterauth.CallInput{Headers: h})
				if err != nil {
					return err
				}
				var out struct{ Token string }
				if err := r.Decode(&out); err != nil {
					return err
				}
				token = out.Token
				return nil
			})
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("deadlock: getToken inside a transaction did not finish")
		}
		if token == "" {
			t.Fatal("no token")
		}
	})
}

func TestToExpJWT(t *testing.T) {
	const iat = 1000
	eq := func(t *testing.T, v any, want int64) {
		t.Helper()
		got, err := jwt.ToExpJWT(v, iat)
		if err != nil || got != want {
			t.Fatalf("ToExpJWT(%v) = %d, %v; want %d", v, got, err, want)
		}
	}
	t.Run("with number input/should return the number as-is", func(t *testing.T) {
		eq(t, 3600, 3600)
		eq(t, 0, 0)
		eq(t, 9999999, 9999999)
	})
	t.Run("with Date input/should convert Date to seconds timestamp", func(t *testing.T) {
		d := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		eq(t, d, d.Unix())
	})
	t.Run("with Date input/should floor milliseconds", func(t *testing.T) {
		eq(t, time.UnixMilli(1704067200500), 1704067200)
	})
	t.Run("with valid TimeString input/should parse short format and add to iat", func(t *testing.T) {
		eq(t, "1h", iat+3600)
		eq(t, "7d", iat+604800)
		eq(t, "30m", iat+1800)
		eq(t, "1s", iat+1)
	})
	t.Run("with valid TimeString input/should parse long format and add to iat", func(t *testing.T) {
		eq(t, "1 hour", iat+3600)
		eq(t, "7 days", iat+604800)
		eq(t, "30 minutes", iat+1800)
	})
	t.Run("with valid TimeString input/should handle negative values", func(t *testing.T) {
		eq(t, "-1h", iat-3600)
		eq(t, "1h ago", iat-3600)
	})
	t.Run("with invalid string input/should throw TypeError for invalid format", func(t *testing.T) {
		for _, s := range []string{"invalid", "", "abc123"} {
			if _, err := jwt.ToExpJWT(s, iat); !errors.Is(err, jwt.ErrInvalidTimeString) {
				t.Fatalf("%q: %v", s, err)
			}
		}
	})
}

func TestJWTClientTypes(t *testing.T) {
	t.Run("should be assignable to BetterAuthClientPlugin", func(t *testing.T) {
		t.Skip("TypeScript-only: client plugin type assignability")
	})
	t.Run("should preserve additional user fields when combined with inferAdditionalFields", func(t *testing.T) {
		t.Skip("TypeScript-only: client type inference")
	})
}

// ---- helpers shared by the signJWT unit tests ----

func decodeHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func nowPayload(sub string) *jsonx.Object {
	return jsonx.O("sub", sub, "iat", float64(time.Now().Unix()))
}

var _ = fmt.Sprintf
