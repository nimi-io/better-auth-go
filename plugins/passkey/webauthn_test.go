package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// ---- open-api.test.ts ----

func endpointByKey(t *testing.T, ti *instance, key string) *betterauth.Endpoint {
	t.Helper()
	for _, ep := range ti.auth.Endpoints() {
		if ep.Key == key {
			return ep
		}
	}
	t.Fatalf("endpoint %s not found", key)
	return nil
}

func openapiOf(t *testing.T, ep *betterauth.Endpoint) map[string]any {
	t.Helper()
	b, err := jsonx.Marshal(ep.Metadata["openapi"])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func TestPasskeyOpenAPI(t *testing.T) {
	ti := newInstance(t, Options{})
	t.Run("should place passkey query parameters at the operation level", func(t *testing.T) {
		op := openapiOf(t, endpointByKey(t, ti, "generatePasskeyRegistrationOptions"))
		params, _ := op["parameters"].([]any)
		want := map[string]bool{"authenticatorAttachment": false, "name": false, "context": false}
		for _, p := range params {
			m := p.(map[string]any)
			n := m["name"].(string)
			if m["in"] != "query" || m["required"] != false {
				t.Fatalf("%v", m)
			}
			if n == "authenticatorAttachment" {
				s := m["schema"].(map[string]any)
				enum, _ := json.Marshal(s["enum"])
				if s["type"] != "string" || string(enum) != `["platform","cross-platform"]` {
					t.Fatalf("%v", s)
				}
			}
			want[n] = true
		}
		for k, ok := range want {
			if !ok {
				t.Fatalf("missing parameter %s", k)
			}
		}
		if _, ok := op["responses"].(map[string]any)["200"].(map[string]any)["parameters"]; ok {
			t.Fatal("parameters must not be on the response")
		}
	})
	t.Run("should require the registration response in the request body", func(t *testing.T) {
		// The request body schema is generated from the zod body by the openAPI plugin; here
		// the equivalent check is that the body schema rejects a missing response.
		res := ti.fetch("POST", "/passkey/verify-registration", http.Header{}, nil, map[string]any{}, false)
		if res.Status != 400 || !strings.Contains(string(res.Body), "[body.response] Invalid input: expected nonoptional, received undefined") {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should describe the optional registration session response", func(t *testing.T) {
		op := openapiOf(t, endpointByKey(t, ti, "verifyPasskeyRegistration"))
		schema := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"]
		got, _ := json.Marshal(schema)
		want := `{"allOf":[{"$ref":"#/components/schemas/Passkey"},{"properties":{"session":{"$ref":"#/components/schemas/Session"},"user":{"$ref":"#/components/schemas/User"}},"type":"object"}],"type":"object"}`
		if string(got) != want {
			t.Fatalf("got %s", got)
		}
	})
}

// ---- authenticator-metadata.test.ts ----

func TestGetAuthenticatorName(t *testing.T) {
	t.Run("resolves known AAGUIDs", func(t *testing.T) {
		for id, name := range map[string]string{
			"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
			"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
			"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
			"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
			"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
		} {
			if got := GetAuthenticatorName(id); got != name {
				t.Fatalf("%s: %q", id, got)
			}
		}
	})
	t.Run("resolves every AAGUID of a multi-AAGUID provider", func(t *testing.T) {
		for _, id := range []string{"08987058-cadc-4b81-b6e1-30de50dcbe96", "9ddd1817-af5a-4672-a2b9-3e3dd95000a9", "6028b017-b1d4-4c02-b4b3-afcdafc96bb2"} {
			if GetAuthenticatorName(id) != "Windows Hello" {
				t.Fatal(id)
			}
		}
	})
	t.Run("normalizes casing and whitespace", func(t *testing.T) {
		if GetAuthenticatorName("  DD4EC289-E01D-41C9-BB89-70FA845D4BF2  ") != "iCloud Keychain (Managed)" {
			t.Fatal()
		}
	})
	t.Run("returns undefined for the all-zero AAGUID, even if added to the map", func(t *testing.T) {
		zero := "00000000-0000-0000-0000-000000000000"
		if GetAuthenticatorName(zero) != "" {
			t.Fatal()
		}
		CommonAuthenticatorNames[zero] = "Spoofed Provider"
		defer delete(CommonAuthenticatorNames, zero)
		if GetAuthenticatorName(zero) != "" {
			t.Fatal()
		}
	})
	t.Run("returns undefined for unknown, empty, or missing input", func(t *testing.T) {
		for _, id := range []string{"11111111-1111-1111-1111-111111111111", "", "   "} {
			if GetAuthenticatorName(id) != "" {
				t.Fatal(id)
			}
		}
	})
	t.Run("does not leak inherited object properties through index lookup", func(t *testing.T) {
		for _, k := range []string{"__proto__", "constructor", "toString", "valueOf"} {
			if GetAuthenticatorName(k) != "" {
				t.Fatal(k)
			}
		}
	})
	t.Run("exposes the raw map so consumers can extend it", func(t *testing.T) {
		extended := map[string]string{"11111111-1111-1111-1111-111111111111": "My Provider"}
		for k, v := range CommonAuthenticatorNames {
			extended[k] = v
		}
		if extended["11111111-1111-1111-1111-111111111111"] != "My Provider" || extended["ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"] != "Google Password Manager" {
			t.Fatal()
		}
	})
}

// ---- simplewebauthn compatibility (testdata generated by e2e/scripts/gen-passkey-fixtures.mjs) ----

type fixtures struct {
	Origin  string          `json:"origin"`
	RPID    string          `json:"rpID"`
	Options json.RawMessage `json:"options"`
	Cases   []struct {
		Attestation  string `json:"attestation"`
		Registration struct {
			Challenge string         `json:"challenge"`
			Response  map[string]any `json:"response"`
		} `json:"registration"`
		Row struct {
			CredentialID string  `json:"credentialID"`
			PublicKey    string  `json:"publicKey"`
			Counter      float64 `json:"counter"`
			DeviceType   string  `json:"deviceType"`
			Transports   string  `json:"transports"`
			BackedUp     bool    `json:"backedUp"`
			AAGUID       string  `json:"aaguid"`
		} `json:"row"`
		Authentication struct {
			Challenge  string         `json:"challenge"`
			Response   map[string]any `json:"response"`
			NewCounter uint32         `json:"newCounter"`
		} `json:"authentication"`
	} `json:"cases"`
}

func loadFixtures(t *testing.T) *fixtures {
	t.Helper()
	b, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func TestRegistrationOptionsMatchSimpleWebAuthn(t *testing.T) {
	f := loadFixtures(t)
	sel := jsonx.O("residentKey", "preferred", "userVerification", "preferred", "authenticatorAttachment", "platform")
	opts, err := GenerateRegistrationOptions(GenerateRegistrationOptionsInput{
		RPName: "Better Auth", RPID: "localhost", UserID: []byte("abcdefghijklmnopqrstuvwxyz012345"),
		UserName: "test@test.com", UserDisplayName: "test@test.com", AttestationType: "none",
		Challenge: bytes.Repeat([]byte{7}, 32),
		ExcludeCredentials: []CredentialDescriptor{
			{ID: "Y3JlZC0x", Transports: []string{"internal", "hybrid"}},
			{ID: "Y3JlZC0y==", Transports: []string{""}},
			{ID: "Y3JlZC0z"},
		},
		AuthenticatorSelection: sel,
		Extensions:             jsonx.O("credProps", false, "minPinLength", true),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := jsonx.Marshal(opts)
	var want bytes.Buffer
	_ = json.Compact(&want, f.Options)
	if string(got) != want.String() {
		t.Fatalf("options differ (incl. key order)\n go: %s\n ts: %s", got, want.String())
	}
	if _, err := GenerateRegistrationOptions(GenerateRegistrationOptionsInput{ExcludeCredentials: []CredentialDescriptor{{ID: "not base64url!"}}}); err == nil {
		t.Fatal("expected invalid credential id error")
	}
}

func TestSimpleWebAuthnFixtures(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Cases {
		t.Run(c.Attestation, func(t *testing.T) {
			v, err := VerifyRegistrationResponse(VerifyRegistrationInput{Response: c.Registration.Response,
				ExpectedChallenge: c.Registration.Challenge, ExpectedOrigin: []string{f.Origin}, ExpectedRPID: []string{f.RPID}})
			if err != nil || !v.Verified {
				t.Fatalf("%v %v", v, err)
			}
			info := v.RegistrationInfo
			if pk := base64.StdEncoding.EncodeToString(info.Credential.PublicKey); pk != c.Row.PublicKey {
				t.Fatalf("publicKey %s != %s", pk, c.Row.PublicKey)
			}
			if info.Credential.ID != c.Row.CredentialID || info.AAGUID != c.Row.AAGUID || info.CredentialDeviceType != c.Row.DeviceType ||
				info.CredentialBackedUp != c.Row.BackedUp || float64(info.Credential.Counter) != c.Row.Counter || info.Fmt != c.Attestation {
				t.Fatalf("info %+v row %+v", info, c.Row)
			}
			// A credential row stored by the TypeScript plugin verifies on Go.
			key, err := base64.StdEncoding.DecodeString(c.Row.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			a, err := VerifyAuthenticationResponse(VerifyAuthenticationInput{Response: c.Authentication.Response,
				ExpectedChallenge: c.Authentication.Challenge, ExpectedOrigin: []string{f.Origin}, ExpectedRPID: []string{f.RPID},
				Credential: CredentialRecord{ID: c.Row.CredentialID, PublicKey: key, Counter: uint32(c.Row.Counter)}})
			if err != nil || !a.Verified || a.AuthenticationInfo.NewCounter != c.Authentication.NewCounter {
				t.Fatalf("%+v %v", a, err)
			}
			if _, err := VerifyAuthenticationResponse(VerifyAuthenticationInput{Response: c.Authentication.Response,
				ExpectedChallenge: "other", ExpectedOrigin: []string{f.Origin}, ExpectedRPID: []string{f.RPID},
				Credential: CredentialRecord{ID: c.Row.CredentialID, PublicKey: key}}); err == nil {
				t.Fatal("wrong challenge accepted")
			}
		})
	}
}

// ---- real ceremonies with the software authenticator ----

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return m
}

func TestRealCeremonies(t *testing.T) {
	for _, attestation := range []string{"none", "packed"} {
		t.Run(attestation, func(t *testing.T) {
			ti := newInstance(t, Options{})
			authr := newSoftAuthenticator(t, testOrigin, attestation)
			headers, user := ti.signInWithTestUser()
			headers.Set("origin", testOrigin)

			res := ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
			opts := decodeJSON(t, res.Body)
			if opts["rp"].(map[string]any)["id"] != "localhost" || opts["rp"].(map[string]any)["name"] != "Better Auth" {
				t.Fatalf("%v", opts["rp"])
			}
			reg := ti.fetch("POST", "/passkey/verify-registration", headers, nil, map[string]any{"response": authr.register(opts), "name": "My key"}, false)
			if reg.Status != 200 {
				t.Fatalf("%d %s", reg.Status, reg.Body)
			}
			row := decodeJSON(t, reg.Body)
			if row["credentialID"] != authr.credentialID() || row["userId"] != user["id"] || row["transports"] != "internal,hybrid" ||
				row["aaguid"] != googleAAGUID || row["deviceType"] != "singleDevice" || row["backedUp"] != false || row["name"] != "My key" {
				t.Fatalf("%v", row)
			}
			if row["publicKey"] != base64.StdEncoding.EncodeToString(authr.coseKey()) {
				t.Fatalf("publicKey %v", row["publicKey"])
			}

			// excludeCredentials / allowCredentials now carry the credential.
			res = ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, false)
			exc, _ := json.Marshal(decodeJSON(t, res.Body)["excludeCredentials"])
			if string(exc) != `[{"id":"`+authr.credentialID()+`","transports":["internal","hybrid"],"type":"public-key"}]` {
				t.Fatalf("%s", exc)
			}

			// discoverable sign-in without a session
			anon := http.Header{}
			anon.Set("origin", testOrigin)
			res = ti.fetch("GET", "/passkey/generate-authenticate-options", anon, nil, nil, true)
			aopts := decodeJSON(t, res.Body)
			signIn := ti.fetch("POST", "/passkey/verify-authentication", anon, nil, map[string]any{"response": authr.authenticate(aopts)}, true)
			if signIn.Status != 200 {
				t.Fatalf("%d %s", signIn.Status, signIn.Body)
			}
			out := decodeJSON(t, signIn.Body)
			if out["user"].(map[string]any)["id"] != user["id"] || !strings.Contains(anon.Get("Cookie"), "better-auth.session_token=") {
				t.Fatalf("%v %q", out, anon.Get("Cookie"))
			}
			rows := ti.findPasskeys(adapter.Where{Field: "credentialID", Value: authr.credentialID()})
			if num(rows[0]["counter"]) != 1 {
				t.Fatalf("counter %v", rows[0]["counter"])
			}
			s, err := ti.auth.API.GetSession(context.Background(), anon)
			if err != nil || s == nil || s.User.ID != user["id"] {
				t.Fatalf("%v %v", s, err)
			}

			// session sign-in lists allowCredentials
			res = ti.fetch("GET", "/passkey/generate-authenticate-options", headers, nil, nil, true)
			aopts = decodeJSON(t, res.Body)
			allow, _ := json.Marshal(aopts["allowCredentials"])
			if !strings.Contains(string(allow), authr.credentialID()) {
				t.Fatalf("%s", allow)
			}
			// a replayed (non-increasing) counter is rejected
			authr.counter = 0
			replay := ti.fetch("POST", "/passkey/verify-authentication", headers, nil, map[string]any{"response": authr.authenticate(aopts)}, false)
			if replay.Status != 400 || decodeJSON(t, replay.Body)["code"] != "AUTHENTICATION_FAILED" {
				t.Fatalf("%d %s", replay.Status, replay.Body)
			}
		})
	}
}

func TestRealCeremonyFailures(t *testing.T) {
	ti := newInstance(t, Options{})
	headers, _ := ti.signInWithTestUser()
	headers.Set("origin", testOrigin)

	register := func(a *softAuthenticator, mutate func(map[string]any)) *httpResult {
		res := ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		resp := a.register(decodeJSON(t, res.Body))
		if mutate != nil {
			mutate(resp)
		}
		return ti.fetch("POST", "/passkey/verify-registration", headers, nil, map[string]any{"response": resp}, false)
	}
	t.Run("wrong origin", func(t *testing.T) {
		r := register(newSoftAuthenticator(t, "http://evil.example.com", "none"), nil)
		if r.Status != 500 || decodeJSON(t, r.Body)["code"] != "FAILED_TO_VERIFY_REGISTRATION" {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("challenge is single use", func(t *testing.T) {
		a := newSoftAuthenticator(t, testOrigin, "none")
		res := ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		resp := a.register(decodeJSON(t, res.Body))
		if r := ti.fetch("POST", "/passkey/verify-registration", headers, nil, map[string]any{"response": resp}, false); r.Status != 200 {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
		r := ti.fetch("POST", "/passkey/verify-registration", headers, nil, map[string]any{"response": resp}, false)
		if r.Status != 400 || decodeJSON(t, r.Body)["code"] != "CHALLENGE_NOT_FOUND" {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("bad packed signature", func(t *testing.T) {
		a := newSoftAuthenticator(t, testOrigin, "packed")
		a.corruptSig = true
		r := register(a, nil)
		if r.Status != 400 || decodeJSON(t, r.Body)["code"] != "FAILED_TO_VERIFY_REGISTRATION" {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("missing origin", func(t *testing.T) {
		h := headers.Clone()
		h.Del("origin")
		res, _, err := ti.call("verifyPasskeyRegistration", h, map[string]any{"response": map[string]any{}}, nil)
		_ = res
		expectAPIError(t, err, "BAD_REQUEST", "FAILED_TO_VERIFY_REGISTRATION")
		_, _, err = ti.call("verifyPasskeyAuthentication", h, map[string]any{"response": map[string]any{}}, nil)
		e := apiErr(t, err)
		if e.Status != "BAD_REQUEST" || e.Message() != "origin missing" {
			t.Fatalf("%v", e)
		}
	})
	t.Run("rpID mismatch", func(t *testing.T) {
		ti2 := newInstance(t, Options{RPID: "example.com"})
		h, _ := ti2.signInWithTestUser()
		h.Set("origin", testOrigin)
		res := ti2.fetch("GET", "/passkey/generate-register-options", h, nil, nil, true)
		opts := decodeJSON(t, res.Body)
		opts["rp"].(map[string]any)["id"] = "localhost"
		r := ti2.fetch("POST", "/passkey/verify-registration", h, nil, map[string]any{"response": newSoftAuthenticator(t, testOrigin, "none").register(opts)}, false)
		if r.Status != 500 {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
}

// client.test.ts covers the browser client (getPasskeyActions with mocked
// @simplewebauthn/browser); there is no Go counterpart. The client is exercised against
// the Go server by e2e/tests/plugin-passkey.test.mjs.
func TestPasskeyClient(t *testing.T) {
	for _, name := range []string{
		"merges registration extensions and returns WebAuthn response",
		"merges authentication extensions and returns WebAuthn response",
		"returns an auth error without logging expected authentication ceremony failures",
		"forwards createSession and notifies the session signal",
		"does not notify the session signal when registration does not return a session",
	} {
		t.Run(name, func(t *testing.T) { t.Skip("TS-only: browser client code (client.ts)") })
	}
}
