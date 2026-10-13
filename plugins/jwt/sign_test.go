package jwt_test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

type provision struct {
	alg        string
	noAlg      bool // persistAlg: false
	expiresAt  *time.Time
	createdAt  *time.Time
	encryptFor *betterauth.AuthContext
}

// provisionKey inserts a jwks row directly (provisionKey in the upstream tests).
func provisionKey(t *testing.T, in *instance, p provision) *jwt.Jwk {
	t.Helper()
	kp, err := jwt.GenerateExportedKeyPair(&jwt.Options{JWKS: &jwt.JWKSOptions{KeyPairConfig: &jwt.JWKOptions{Alg: p.alg}}})
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	if p.createdAt != nil {
		created = *p.createdAt
	}
	data := adapter.Record{
		"publicKey":  string(jsonx.MustMarshal(jose.ExportJWK(kp.PublicWebKey))),
		"privateKey": string(jsonx.MustMarshal(jose.ExportJWK(kp.PrivateWebKey))),
		"createdAt":  created,
	}
	if !p.noAlg {
		data["alg"] = p.alg
	}
	if p.expiresAt != nil {
		data["expiresAt"] = *p.expiresAt
	}
	r, err := in.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "jwks", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return &jwt.Jwk{ID: r["id"].(string), Alg: p.alg}
}

var plainOpts = jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true}}

func bootJWT(t *testing.T, o jwt.Options) *instance {
	return newInstance(t, withJWT(o))
}

func sign(t *testing.T, in *instance, o jwt.Options, cfg jwt.SignConfig) (string, error) {
	t.Helper()
	cfg.Options = &o
	if cfg.Payload == nil {
		cfg.Payload = nowPayload("u1")
	}
	return jwt.SignJWT(in.ctx(), cfg)
}

func mustSign(t *testing.T, in *instance, o jwt.Options, cfg jwt.SignConfig) string {
	t.Helper()
	tok, err := sign(t, in, o, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func expectErr(t *testing.T, err error, pattern string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error matching %s", pattern)
	}
	if !regexp.MustCompile(pattern).MatchString(err.Error()) {
		t.Fatalf("error %q does not match %s", err, pattern)
	}
}

func allRows(t *testing.T, in *instance) []adapter.Record {
	t.Helper()
	rows, err := in.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "jwks"})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func later(d time.Duration) *time.Time { v := time.Now().Add(d); return &v }

// ---- sign-overrides.test.ts ----

func TestSignJWTSigningKeyOverrides(t *testing.T) {
	t.Run("uses the latest key when neither signingKeyId nor signingAlgorithm is set", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		k := provisionKey(t, in, provision{alg: "EdDSA"})
		h := decodeHeader(t, mustSign(t, in, plainOpts, jwt.SignConfig{}))
		if h["kid"] != k.ID || h["alg"] != "EdDSA" {
			t.Fatalf("header %v", h)
		}
	})
	t.Run("signingKeyId routes through getKeyById and overrides latest-key selection", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		older := provisionKey(t, in, provision{alg: "ES256"})
		time.Sleep(5 * time.Millisecond)
		provisionKey(t, in, provision{alg: "EdDSA"})
		h := decodeHeader(t, mustSign(t, in, plainOpts, jwt.SignConfig{SigningKeyID: older.ID}))
		if h["kid"] != older.ID || h["alg"] != "ES256" {
			t.Fatalf("header %v", h)
		}
	})
	t.Run("signingAlgorithm picks the most recent key with that alg", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA"})
		time.Sleep(5 * time.Millisecond)
		newer := provisionKey(t, in, provision{alg: "EdDSA"})
		time.Sleep(5 * time.Millisecond)
		provisionKey(t, in, provision{alg: "ES256"})
		h := decodeHeader(t, mustSign(t, in, plainOpts, jwt.SignConfig{SigningAlgorithm: "EdDSA"}))
		if h["kid"] != newer.ID || h["alg"] != "EdDSA" {
			t.Fatalf("header %v", h)
		}
	})
	t.Run("signingKeyId pointing at a missing key throws (does not silently fall back)", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA"})
		_, err := sign(t, in, plainOpts, jwt.SignConfig{SigningKeyID: "nonexistent-kid"})
		expectErr(t, err, `(?i)signingKeyId.*not found`)
	})
	t.Run("signingAlgorithm with no matching key throws (does not auto-mint)", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA"})
		_, err := sign(t, in, plainOpts, jwt.SignConfig{SigningAlgorithm: "ES256"})
		expectErr(t, err, `(?i)no key with alg "ES256"`)
	})
	t.Run("signingKeyId + mismatched signingAlgorithm throws to surface the conflict", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		ed := provisionKey(t, in, provision{alg: "EdDSA"})
		_, err := sign(t, in, plainOpts, jwt.SignConfig{SigningKeyID: ed.ID, SigningAlgorithm: "ES256"})
		expectErr(t, err, `alg "EdDSA".*signingAlgorithm.*"ES256"`)
	})
	t.Run("signingKeyId + matching signingAlgorithm succeeds", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		ed := provisionKey(t, in, provision{alg: "EdDSA"})
		h := decodeHeader(t, mustSign(t, in, plainOpts, jwt.SignConfig{SigningKeyID: ed.ID, SigningAlgorithm: "EdDSA"}))
		if h["kid"] != ed.ID {
			t.Fatalf("header %v", h)
		}
	})
}

func TestJWKSAdapterHelpers(t *testing.T) {
	t.Run("getKeyById finds a provisioned key", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		k := provisionKey(t, in, provision{alg: "EdDSA"})
		found, err := jwt.GetJwksAdapter(nil).GetKeyByID(in.ctx(), k.ID)
		if err != nil || found == nil || found.ID != k.ID {
			t.Fatalf("found %+v %v", found, err)
		}
	})
	t.Run("getKeyById returns undefined for an unknown id", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA"})
		found, err := jwt.GetJwksAdapter(nil).GetKeyByID(in.ctx(), "no-such-kid")
		if err != nil || found != nil {
			t.Fatalf("found %+v %v", found, err)
		}
	})
	t.Run("getLatestKeyByAlg returns the most recent key matching the algorithm", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA"})
		time.Sleep(5 * time.Millisecond)
		newer := provisionKey(t, in, provision{alg: "EdDSA"})
		time.Sleep(5 * time.Millisecond)
		provisionKey(t, in, provision{alg: "ES256"})
		found, _ := jwt.GetJwksAdapter(nil).GetLatestKeyByAlg(in.ctx(), "EdDSA")
		if found == nil || found.ID != newer.ID {
			t.Fatalf("found %+v", found)
		}
	})
	t.Run("getLatestKeyByAlg returns undefined when no matching key exists", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA"})
		found, _ := jwt.GetJwksAdapter(nil).GetLatestKeyByAlg(in.ctx(), "ES256")
		if found != nil {
			t.Fatalf("found %+v", found)
		}
	})
}

// ---- multi-alg.test.ts ----

func remoteSignOpts(sign func(*betterauth.EndpointContext, *jsonx.Object, *jwt.Header, jwt.SigningConfig) (string, error)) jwt.Options {
	return jwt.Options{
		JWKS: &jwt.JWKSOptions{RemoteURL: "https://example.test/jwks.json", KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"}},
		JWT:  &jwt.JWTOptions{Sign: sign},
	}
}

func TestCustomSignReceivesSigningOverrides(t *testing.T) {
	t.Run("forwards signingKeyId and signingAlgorithm to the custom signer", func(t *testing.T) {
		var calls []jwt.SigningConfig
		var payloads []*jsonx.Object
		o := remoteSignOpts(func(_ *betterauth.EndpointContext, p *jsonx.Object, _ *jwt.Header, c jwt.SigningConfig) (string, error) {
			calls = append(calls, c)
			payloads = append(payloads, p)
			return "signed.by.kms", nil
		})
		in := bootJWT(t, o)
		tok := mustSign(t, in, o, jwt.SignConfig{SigningKeyID: "kms-key-1", SigningAlgorithm: "ES256"})
		if tok != "signed.by.kms" || len(calls) != 1 {
			t.Fatalf("token %q calls %d", tok, len(calls))
		}
		if sub, _ := payloads[0].Get("sub"); sub != "u1" {
			t.Fatalf("sub %v", sub)
		}
		if calls[0] != (jwt.SigningConfig{SigningKeyID: "kms-key-1", SigningAlgorithm: "ES256"}) {
			t.Fatalf("config %+v", calls[0])
		}
	})
	t.Run("passes signingConfig with undefined fields when no overrides are set (back-compat)", func(t *testing.T) {
		var calls []jwt.SigningConfig
		o := remoteSignOpts(func(_ *betterauth.EndpointContext, _ *jsonx.Object, _ *jwt.Header, c jwt.SigningConfig) (string, error) {
			calls = append(calls, c)
			return "default.signed.token", nil
		})
		in := bootJWT(t, o)
		mustSign(t, in, o, jwt.SignConfig{})
		if len(calls) != 1 || calls[0] != (jwt.SigningConfig{}) {
			t.Fatalf("calls %+v", calls)
		}
	})
	t.Run("legacy single-arg signer implementations still work (extra args ignored)", func(t *testing.T) {
		o := remoteSignOpts(func(_ *betterauth.EndpointContext, p *jsonx.Object, _ *jwt.Header, _ jwt.SigningConfig) (string, error) {
			sub, _ := p.Get("sub")
			s, _ := sub.(string)
			if s == "" {
				s = "anon"
			}
			return "legacy." + s, nil
		})
		in := bootJWT(t, o)
		tok := mustSign(t, in, o, jwt.SignConfig{Payload: nowPayload("u2"), SigningKeyID: "remote-key-7"})
		if tok != "legacy.u2" {
			t.Fatalf("token %q", tok)
		}
		// The arity assertion (signer receives three arguments) is TypeScript-specific: the Go
		// Sign signature always receives payload, header and signing config.
	})
}

func TestGetLatestKeyByAlgLegacyRowFallback(t *testing.T) {
	edOpts := jwt.Options{JWKS: &jwt.JWKSOptions{KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"}}}
	t.Run("matches legacy rows (alg: null) against configured keyPairConfig.alg", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		legacy := provisionKey(t, in, provision{alg: "EdDSA", noAlg: true})
		found, _ := jwt.GetJwksAdapter(&edOpts).GetLatestKeyByAlg(in.ctx(), "EdDSA")
		if found == nil || found.ID != legacy.ID {
			t.Fatalf("found %+v", found)
		}
	})
	t.Run("does NOT match legacy rows against a non-default alg", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "EdDSA", noAlg: true})
		found, _ := jwt.GetJwksAdapter(&edOpts).GetLatestKeyByAlg(in.ctx(), "ES256")
		if found != nil {
			t.Fatalf("found %+v", found)
		}
	})
	t.Run("matches legacy rows against a non-default configured alg", func(t *testing.T) {
		esOpts := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "ES256"}}}
		in := bootJWT(t, esOpts)
		legacy := provisionKey(t, in, provision{alg: "ES256", noAlg: true})
		ad := jwt.GetJwksAdapter(&jwt.Options{JWKS: &jwt.JWKSOptions{KeyPairConfig: &jwt.JWKOptions{Alg: "ES256"}}})
		found, _ := ad.GetLatestKeyByAlg(in.ctx(), "ES256")
		if found == nil || found.ID != legacy.ID {
			t.Fatalf("found %+v", found)
		}
		if neg, _ := ad.GetLatestKeyByAlg(in.ctx(), "EdDSA"); neg != nil {
			t.Fatalf("negative %+v", neg)
		}
	})
	t.Run("explicit-alg rows still win over legacy fallback when both match", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		older := provisionKey(t, in, provision{alg: "EdDSA", noAlg: true, createdAt: later(-time.Minute)})
		newer := provisionKey(t, in, provision{alg: "EdDSA", createdAt: later(0)})
		found, _ := jwt.GetJwksAdapter(&edOpts).GetLatestKeyByAlg(in.ctx(), "EdDSA")
		if found == nil || found.ID != newer.ID || found.ID == older.ID {
			t.Fatalf("found %+v", found)
		}
	})
	t.Run("signJWT honors legacy-row alg fallback end-to-end", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		legacy := provisionKey(t, in, provision{alg: "EdDSA", noAlg: true})
		h := decodeHeader(t, mustSign(t, in, plainOpts, jwt.SignConfig{SigningAlgorithm: "EdDSA"}))
		if h["kid"] != legacy.ID || h["alg"] != "EdDSA" {
			t.Fatalf("header %v", h)
		}
	})
}

func TestExpiredKeyFilteringInsideAdapterLookups(t *testing.T) {
	t.Run("getLatestKey skips expired rows even when they are the newest", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		live := provisionKey(t, in, provision{alg: "EdDSA", createdAt: later(-time.Minute)})
		provisionKey(t, in, provision{alg: "EdDSA", createdAt: later(0), expiresAt: later(-time.Second)})
		found, _ := jwt.GetJwksAdapter(&plainOpts).GetLatestKey(in.ctx())
		if found == nil || found.ID != live.ID {
			t.Fatalf("found %+v", found)
		}
	})
	t.Run("getLatestKeyByAlg skips expired rows even when they are the newest", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		live := provisionKey(t, in, provision{alg: "EdDSA", createdAt: later(-time.Minute)})
		provisionKey(t, in, provision{alg: "EdDSA", createdAt: later(0), expiresAt: later(-time.Second)})
		found, _ := jwt.GetJwksAdapter(&plainOpts).GetLatestKeyByAlg(in.ctx(), "EdDSA")
		if found == nil || found.ID != live.ID {
			t.Fatalf("found %+v", found)
		}
	})
	t.Run("getLatestKeyByAlg returns undefined when all matches are expired", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		provisionKey(t, in, provision{alg: "ES256", expiresAt: later(-time.Second)})
		found, _ := jwt.GetJwksAdapter(&plainOpts).GetLatestKeyByAlg(in.ctx(), "ES256")
		if found != nil {
			t.Fatalf("found %+v", found)
		}
	})
}

func TestPinnedKidAgainstLegacyRows(t *testing.T) {
	t.Run("accepts a legacy row when signingAlgorithm matches keyPairConfig.alg (default EdDSA)", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		legacy := provisionKey(t, in, provision{alg: "EdDSA", noAlg: true})
		if tok := mustSign(t, in, plainOpts, jwt.SignConfig{SigningKeyID: legacy.ID, SigningAlgorithm: "EdDSA"}); tok == "" {
			t.Fatal("empty token")
		}
	})
	t.Run("throws when pinned signingAlgorithm differs from the legacy row's effective alg", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		legacy := provisionKey(t, in, provision{alg: "EdDSA", noAlg: true})
		_, err := sign(t, in, plainOpts, jwt.SignConfig{SigningKeyID: legacy.ID, SigningAlgorithm: "ES256"})
		expectErr(t, err, `inherits keyPairConfig\.alg`)
	})
}

func TestJWKSAlgCrvPersistence(t *testing.T) {
	t.Run("persists alg and crv on a freshly-minted EdDSA key", func(t *testing.T) {
		in := bootJWT(t, plainOpts)
		mustSign(t, in, plainOpts, jwt.SignConfig{})
		rows := allRows(t, in)
		if len(rows) == 0 || rows[0]["alg"] != "EdDSA" || rows[0]["crv"] != "Ed25519" {
			t.Fatalf("rows %v", rows)
		}
	})
	t.Run("persists alg and crv on a freshly-minted ES256 key", func(t *testing.T) {
		o := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "ES256"}}}
		in := bootJWT(t, o)
		mustSign(t, in, o, jwt.SignConfig{})
		rows := allRows(t, in)
		if len(rows) == 0 || rows[0]["alg"] != "ES256" || rows[0]["crv"] != "P-256" {
			t.Fatalf("rows %v", rows)
		}
	})
}

func countAlg(rows []adapter.Record, alg string) []adapter.Record {
	var out []adapter.Record
	for _, r := range rows {
		if r["alg"] == alg {
			out = append(out, r)
		}
	}
	return out
}

func TestKeyPairConfigsLazyMint(t *testing.T) {
	multi := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"},
		KeyPairConfigs: []jwt.JWKOptions{{Alg: "ES256"}}}}
	t.Run("lazy-mints a key the first time signingAlgorithm pins an alg declared in keyPairConfigs[]", func(t *testing.T) {
		in := bootJWT(t, multi)
		if n := len(countAlg(allRows(t, in), "ES256")); n != 0 {
			t.Fatalf("before %d", n)
		}
		if tok := mustSign(t, in, multi, jwt.SignConfig{SigningAlgorithm: "ES256"}); tok == "" {
			t.Fatal("empty")
		}
		es := countAlg(allRows(t, in), "ES256")
		if len(es) != 1 || es[0]["crv"] != "P-256" {
			t.Fatalf("after %v", es)
		}
	})
	t.Run("sequential signJWT calls reuse the lazy-minted key (no double-mint within a single thread of execution)", func(t *testing.T) {
		in := bootJWT(t, multi)
		mustSign(t, in, multi, jwt.SignConfig{SigningAlgorithm: "ES256"})
		mustSign(t, in, multi, jwt.SignConfig{Payload: nowPayload("u2"), SigningAlgorithm: "ES256"})
		if n := len(countAlg(allRows(t, in), "ES256")); n != 1 {
			t.Fatalf("rows %d", n)
		}
	})
	t.Run("throws enriched error naming keyPairConfig.alg + keyPairConfigs when the requested alg is not provisioned", func(t *testing.T) {
		o := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"},
			KeyPairConfigs: []jwt.JWKOptions{{Alg: "RS256"}}}}
		in := bootJWT(t, o)
		_, err := sign(t, in, o, jwt.SignConfig{SigningAlgorithm: "ES256"})
		expectErr(t, err, `keyPairConfig\.alg="EdDSA".*keyPairConfigs: RS256.*Add "ES256"`)
	})
	t.Run("declares 'none' for keyPairConfigs in the error message when none are configured", func(t *testing.T) {
		o := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"}}}
		in := bootJWT(t, o)
		_, err := sign(t, in, o, jwt.SignConfig{SigningAlgorithm: "ES256"})
		expectErr(t, err, `keyPairConfigs: none`)
	})
}

func TestPrimaryAlgPinOnEmptyJWKS(t *testing.T) {
	t.Run("lazy-mints when signingAlgorithm equals keyPairConfig.alg and no key exists", func(t *testing.T) {
		o := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"}}}
		in := bootJWT(t, o)
		if n := len(allRows(t, in)); n != 0 {
			t.Fatalf("before %d", n)
		}
		mustSign(t, in, o, jwt.SignConfig{SigningAlgorithm: "EdDSA"})
		rows := allRows(t, in)
		if len(rows) != 1 || rows[0]["alg"] != "EdDSA" {
			t.Fatalf("rows %v", rows)
		}
	})
	t.Run("lazy-mints primary alg even when keyPairConfigs is undefined", func(t *testing.T) {
		o := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "ES256"}}}
		in := bootJWT(t, o)
		mustSign(t, in, o, jwt.SignConfig{SigningAlgorithm: "ES256"})
	})
}

func TestUnpinnedTokensStayOnPrimaryAlg(t *testing.T) {
	t.Run("ID token (unpinned) signs with primary alg even after a non-primary alg is lazy-minted", func(t *testing.T) {
		o := jwt.Options{JWKS: &jwt.JWKSOptions{DisablePrivateKeyEncryption: true, KeyPairConfig: &jwt.JWKOptions{Alg: "EdDSA"},
			KeyPairConfigs: []jwt.JWKOptions{{Alg: "ES256"}}}}
		in := bootJWT(t, o)
		if h := decodeHeader(t, mustSign(t, in, o, jwt.SignConfig{Payload: nowPayload("u-primary")})); h["alg"] != "EdDSA" {
			t.Fatalf("primary %v", h)
		}
		time.Sleep(5 * time.Millisecond)
		mustSign(t, in, o, jwt.SignConfig{Payload: nowPayload("u-extra"), SigningAlgorithm: "ES256"})
		if h := decodeHeader(t, mustSign(t, in, o, jwt.SignConfig{Payload: nowPayload("u-after")})); h["alg"] != "EdDSA" {
			t.Fatalf("unpinned %v", h)
		}
	})
}

// ---- rotation.test.ts ----
// vi.useFakeTimers() is emulated by moving the stored key timestamps back in time.

func TestJWTRotation(t *testing.T) {
	newStore := func() (*[]*jwt.Jwk, *jwt.AdapterOptions) {
		var storage []*jwt.Jwk
		return &storage, &jwt.AdapterOptions{
			GetJwks: func(*betterauth.EndpointContext) ([]*jwt.Jwk, error) { return storage, nil },
			CreateJwk: func(_ *betterauth.EndpointContext, data jwt.Jwk) (*jwt.Jwk, error) {
				data.ID = randomID()
				storage = append(storage, &data)
				return &data, nil
			},
		}
	}
	advance := func(storage []*jwt.Jwk, d time.Duration) {
		for _, k := range storage {
			k.CreatedAt = k.CreatedAt.Add(-d)
			if k.ExpiresAt != nil {
				e := k.ExpiresAt.Add(-d)
				k.ExpiresAt = &e
			}
		}
	}
	signSub := func(t *testing.T, in *instance) {
		t.Helper()
		if _, err := in.call("signJWT", betterauth.CallInput{Body: map[string]any{"payload": map[string]any{"sub": "user1"}}}); err != nil {
			t.Fatal(err)
		}
	}
	jwksKeys := func(t *testing.T, in *instance) []jose.JWK {
		t.Helper()
		r, err := in.call("getJwks", betterauth.CallInput{})
		if err != nil {
			t.Fatal(err)
		}
		var set jose.JWKS
		_ = r.Decode(&set)
		return set.Keys
	}
	t.Run("should rotate keys when expired", func(t *testing.T) {
		storage, ad := newStore()
		in := bootJWT(t, jwt.Options{JWKS: &jwt.JWKSOptions{RotationInterval: time.Second}, Adapter: ad})
		signSub(t, in)
		if len(*storage) != 1 {
			t.Fatalf("keys %d", len(*storage))
		}
		first := (*storage)[0]
		advance(*storage, 1100*time.Millisecond)
		signSub(t, in)
		if len(*storage) != 2 || (*storage)[1].ID == first.ID {
			t.Fatalf("keys %d", len(*storage))
		}
	})
	t.Run("should return keys within grace period", func(t *testing.T) {
		storage, ad := newStore()
		grace := time.Second
		in := bootJWT(t, jwt.Options{JWKS: &jwt.JWKSOptions{RotationInterval: time.Second, GracePeriod: &grace}, Adapter: ad})
		signSub(t, in)
		advance(*storage, 1100*time.Millisecond)
		signSub(t, in)
		if len(*storage) != 2 {
			t.Fatalf("keys %d", len(*storage))
		}
		if keys := jwksKeys(t, in); len(keys) != 2 {
			t.Fatalf("jwks %d", len(keys))
		}
		advance(*storage, 1000*time.Millisecond)
		keys := jwksKeys(t, in)
		if len(keys) != 1 || keys[0].Kid != (*storage)[1].ID {
			t.Fatalf("jwks after grace %+v", keys)
		}
	})
}

func randomID() string { return crypto.RandomUUID() }
