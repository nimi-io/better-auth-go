package passkey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// This file mirrors the parts of @simplewebauthn/server (v13) used by the passkey plugin:
// generateRegistrationOptions, generateAuthenticationOptions, verifyRegistrationResponse
// and verifyAuthenticationResponse. The options are built as ordered JSON objects with the
// same keys, key order and defaults so @simplewebauthn/browser (passkeyClient) consumes
// them unchanged. Attestation statements other than "none" are verified with
// github.com/go-webauthn/webauthn; assertion signatures with its webauthncose package.

// SupportedCOSEAlgorithmIdentifiers are the COSE algorithms accepted for new credentials
// (supportedCOSEAlgorithmIdentifiers).
var SupportedCOSEAlgorithmIdentifiers = []int64{-8, -7, -36, -37, -38, -39, -257, -258, -259, -65535}

// defaultSupportedAlgorithmIDs are advertised in pubKeyCredParams.
var defaultSupportedAlgorithmIDs = []int64{-8, -7, -257}

// CredentialDescriptor is an entry of excludeCredentials / allowCredentials. A nil
// Transports omits the key (JavaScript undefined).
type CredentialDescriptor struct {
	ID         string
	Transports []string
}

// AuthenticatorSelection is AuthenticatorSelectionCriteria. Empty strings and nil
// pointers are unset.
type AuthenticatorSelection struct {
	AuthenticatorAttachment string
	RequireResidentKey      *bool
	ResidentKey             string
	UserVerification        string
}

// GenerateRegistrationOptionsInput is the input of GenerateRegistrationOptions.
type GenerateRegistrationOptionsInput struct {
	RPName          string
	RPID            string
	UserName        string
	UserID          []byte
	UserDisplayName string
	// Challenge defaults to 32 random bytes.
	Challenge []byte
	// Timeout defaults to 60000.
	Timeout         int
	AttestationType string
	// ExcludeCredentials are the user's existing credentials.
	ExcludeCredentials []CredentialDescriptor
	// AuthenticatorSelection is an ordered object; nil uses
	// {residentKey: "preferred", userVerification: "preferred"}.
	AuthenticatorSelection *jsonx.Object
	Extensions             *jsonx.Object
}

func randomChallenge() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// b64url encodes without padding (isoBase64URL.fromBuffer).
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// isBase64URL is isoBase64URL.isBase64URL: padding is ignored, then /^[-A-Za-z0-9_]*$/.
func isBase64URL(s string) bool {
	s = strings.ReplaceAll(s, "=", "")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// fromB64URL is isoBase64URL.toBuffer. Standard-alphabet characters are tolerated.
func fromB64URL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.DecodeString(s)
}

func credentialList(creds []CredentialDescriptor, kind string) ([]any, error) {
	out := make([]any, 0, len(creds))
	for _, c := range creds {
		if !isBase64URL(c.ID) {
			return nil, fmt.Errorf("%s id %q is not a valid base64url string", kind, c.ID)
		}
		o := jsonx.O("id", strings.ReplaceAll(c.ID, "=", ""))
		if c.Transports != nil {
			t := make([]any, len(c.Transports))
			for i, s := range c.Transports {
				t[i] = s
			}
			o.Set("transports", t)
		}
		o.Set("type", "public-key")
		out = append(out, o)
	}
	return out, nil
}

// GenerateRegistrationOptions is generateRegistrationOptions (PublicKeyCredentialCreationOptionsJSON).
func GenerateRegistrationOptions(in GenerateRegistrationOptionsInput) (*jsonx.Object, error) {
	challenge := in.Challenge
	if challenge == nil {
		challenge = randomChallenge()
	}
	timeout := in.Timeout
	if timeout == 0 {
		timeout = 60000
	}
	attestation := in.AttestationType
	if attestation == "" {
		attestation = "none"
	}
	userID := in.UserID
	if len(userID) == 0 {
		userID = make([]byte, 32)
		if _, err := rand.Read(userID); err != nil {
			return nil, err
		}
	}
	params := make([]any, len(defaultSupportedAlgorithmIDs))
	for i, alg := range defaultSupportedAlgorithmIDs {
		params[i] = jsonx.O("alg", alg, "type", "public-key")
	}
	sel := in.AuthenticatorSelection
	if sel == nil {
		sel = jsonx.O("residentKey", "preferred", "userVerification", "preferred")
	} else {
		sel = sel.Clone()
	}
	if rk, ok := sel.Get("residentKey"); !ok || rk == nil {
		if rr, _ := sel.Get("requireResidentKey"); rr == true {
			sel.Set("residentKey", "required")
		}
	} else {
		sel.Set("requireResidentKey", rk == "required")
	}
	exclude, err := credentialList(in.ExcludeCredentials, "excludeCredential")
	if err != nil {
		return nil, err
	}
	ext := jsonx.NewObject()
	if in.Extensions != nil {
		ext = in.Extensions.Clone()
	}
	ext.Set("credProps", true)
	return jsonx.O(
		"challenge", b64url(challenge),
		"rp", jsonx.O("name", in.RPName, "id", in.RPID),
		"user", jsonx.O("id", b64url(userID), "name", in.UserName, "displayName", in.UserDisplayName),
		"pubKeyCredParams", params,
		"timeout", timeout,
		"attestation", attestation,
		"excludeCredentials", exclude,
		"authenticatorSelection", sel,
		"extensions", ext,
		"hints", []any{},
	), nil
}

// GenerateAuthenticationOptionsInput is the input of GenerateAuthenticationOptions.
type GenerateAuthenticationOptionsInput struct {
	RPID string
	// AllowCredentials nil omits the key.
	AllowCredentials []CredentialDescriptor
	Challenge        []byte
	Timeout          int
	UserVerification string
	// Extensions nil omits the key.
	Extensions *jsonx.Object
}

// GenerateAuthenticationOptions is generateAuthenticationOptions
// (PublicKeyCredentialRequestOptionsJSON).
func GenerateAuthenticationOptions(in GenerateAuthenticationOptionsInput) (*jsonx.Object, error) {
	challenge := in.Challenge
	if challenge == nil {
		challenge = randomChallenge()
	}
	timeout := in.Timeout
	if timeout == 0 {
		timeout = 60000
	}
	uv := in.UserVerification
	if uv == "" {
		uv = "preferred"
	}
	o := jsonx.O("rpId", in.RPID, "challenge", b64url(challenge))
	if in.AllowCredentials != nil {
		allow, err := credentialList(in.AllowCredentials, "allowCredential")
		if err != nil {
			return nil, err
		}
		o.Set("allowCredentials", allow)
	}
	o.Set("timeout", timeout)
	o.Set("userVerification", uv)
	if in.Extensions != nil {
		o.Set("extensions", in.Extensions)
	}
	return o, nil
}

// ---- verification ----

// RegistrationCredential is registrationInfo.credential.
type RegistrationCredential struct {
	// ID is the base64url credential id.
	ID string
	// PublicKey is the COSE-encoded credential public key.
	PublicKey  []byte
	Counter    uint32
	Transports []string
}

// RegistrationInfo is VerifiedRegistrationResponse.registrationInfo.
type RegistrationInfo struct {
	Fmt                           string
	AAGUID                        string
	CredentialType                string
	Credential                    RegistrationCredential
	AttestationObject             []byte
	UserVerified                  bool
	CredentialDeviceType          string
	CredentialBackedUp            bool
	Origin                        string
	RPID                          string
	AuthenticatorExtensionResults any
}

// VerifiedRegistrationResponse is the result of VerifyRegistrationResponse.
type VerifiedRegistrationResponse struct {
	Verified         bool
	RegistrationInfo *RegistrationInfo
}

// AuthenticationInfo is VerifiedAuthenticationResponse.authenticationInfo.
type AuthenticationInfo struct {
	NewCounter                    uint32
	CredentialID                  string
	UserVerified                  bool
	CredentialDeviceType          string
	CredentialBackedUp            bool
	AuthenticatorExtensionResults any
	Origin                        string
	RPID                          string
}

// VerifiedAuthenticationResponse is the result of VerifyAuthenticationResponse.
type VerifiedAuthenticationResponse struct {
	Verified           bool
	AuthenticationInfo AuthenticationInfo
}

// VerifyRegistrationInput is the input of VerifyRegistrationResponse.
type VerifyRegistrationInput struct {
	// Response is the RegistrationResponseJSON sent by the browser (decoded JSON).
	Response          any
	ExpectedChallenge string
	ExpectedOrigin    []string
	// ExpectedRPID is skipped when empty.
	ExpectedRPID            []string
	RequireUserVerification bool
	// SkipUserPresence disables the user presence requirement (requireUserPresence: false).
	SkipUserPresence bool
}

// CredentialRecord is the stored credential used to verify an assertion.
type CredentialRecord struct {
	ID         string
	PublicKey  []byte
	Counter    uint32
	Transports []string
}

// VerifyAuthenticationInput is the input of VerifyAuthenticationResponse.
type VerifyAuthenticationInput struct {
	// Response is the AuthenticationResponseJSON sent by the browser (decoded JSON).
	Response                any
	ExpectedChallenge       string
	ExpectedOrigin          []string
	ExpectedRPID            []string
	Credential              CredentialRecord
	RequireUserVerification bool
}

type authFlags struct {
	up, uv, be, bs, at, ed bool
}

type parsedAuthData struct {
	rpIDHash            []byte
	flags               authFlags
	counter             uint32
	aaguid              []byte
	credentialID        []byte
	credentialPublicKey []byte
	extensions          any
}

var badEdDSACBOR, _ = hex.DecodeString("a301634f4b500327206745643235353139")

// parseAuthenticatorData mirrors simplewebauthn's parseAuthenticatorData.
func parseAuthenticatorData(authData []byte) (*parsedAuthData, error) {
	if len(authData) < 37 {
		return nil, fmt.Errorf("Authenticator data was %d bytes, expected at least 37 bytes", len(authData))
	}
	p := &parsedAuthData{rpIDHash: authData[:32]}
	f := authData[32]
	p.flags = authFlags{up: f&1 != 0, uv: f&(1<<2) != 0, be: f&(1<<3) != 0, bs: f&(1<<4) != 0, at: f&(1<<6) != 0, ed: f&(1<<7) != 0}
	p.counter = binary.BigEndian.Uint32(authData[33:37])
	ptr := 37
	if p.flags.at {
		if len(authData) < ptr+18 {
			return nil, errors.New("Authenticator data is too short for attested credential data")
		}
		p.aaguid = authData[ptr : ptr+16]
		ptr += 16
		n := int(binary.BigEndian.Uint16(authData[ptr : ptr+2]))
		ptr += 2
		if len(authData) < ptr+n {
			return nil, errors.New("Authenticator data is too short for the credential id")
		}
		p.credentialID = authData[ptr : ptr+n]
		ptr += n
		rest := authData[ptr:]
		if bytes.HasPrefix(rest, badEdDSACBOR) {
			// { 1: "OKP", 3: -8, -1: "Ed25519" } is missing -2 (x); decode it as a 4-entry map.
			fixed := append([]byte{0xa4}, rest[1:]...)
			var m any
			k, err := webauthncbor.UnmarshalFirst(fixed, &m)
			if err != nil {
				return nil, err
			}
			p.credentialPublicKey = append([]byte(nil), fixed[:k]...)
			ptr += k
		} else {
			var m any
			k, err := webauthncbor.UnmarshalFirst(rest, &m)
			if err != nil {
				return nil, err
			}
			p.credentialPublicKey = append([]byte(nil), rest[:k]...)
			ptr += k
		}
	}
	if p.flags.ed {
		var m any
		k, err := webauthncbor.UnmarshalFirst(authData[ptr:], &m)
		if err != nil {
			return nil, err
		}
		p.extensions = m
		ptr += k
	}
	if len(authData) > ptr {
		return nil, errors.New("Leftover bytes detected while parsing authenticator data")
	}
	return p, nil
}

func backupFlags(f authFlags) (deviceType string, backedUp bool, err error) {
	deviceType = "singleDevice"
	if f.be {
		deviceType = "multiDevice"
	}
	if deviceType == "singleDevice" && f.bs {
		return "", false, errors.New("Single-device credential indicated that it was backed up, which should be impossible.")
	}
	return deviceType, f.bs, nil
}

func matchRPID(hash []byte, expected []string) (string, error) {
	for _, id := range expected {
		h := sha256.Sum256([]byte(id))
		if bytes.Equal(h[:], hash) {
			return id, nil
		}
	}
	return "", errors.New("Unexpected RP ID hash")
}

func aaguidString(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) != 32 {
		return h
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// jsTruthy reports JavaScript truthiness for decoded JSON values.
func jsTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && t == t
	case int:
		return t != 0
	case int64:
		return t != 0
	}
	return true
}

type clientData struct {
	typ, origin, challenge string
	tokenBinding           any
}

func decodeClientData(v any) (*clientData, []byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, nil, errors.New("clientDataJSON was not a string")
	}
	raw, err := fromB64URL(s)
	if err != nil {
		return nil, nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, err
	}
	cd := &clientData{tokenBinding: m["tokenBinding"]}
	cd.typ, _ = m["type"].(string)
	cd.origin, _ = m["origin"].(string)
	cd.challenge, _ = m["challenge"].(string)
	return cd, raw, nil
}

func checkTokenBinding(tb any, statuses ...string) error {
	if !jsTruthy(tb) {
		return nil
	}
	m, ok := tb.(map[string]any)
	if !ok {
		return fmt.Errorf("Unexpected value for TokenBinding %v", tb)
	}
	st, _ := m["status"].(string)
	if !slices.Contains(statuses, st) {
		return fmt.Errorf("Unexpected tokenBinding.status value of %q", st)
	}
	return nil
}

func checkCredentialEnvelope(resp map[string]any) error {
	if !jsTruthy(resp["id"]) {
		return errors.New("Missing credential ID")
	}
	if resp["id"] != resp["rawId"] {
		return errors.New("Credential ID was not base64url-encoded")
	}
	if resp["type"] != "public-key" {
		return fmt.Errorf("Unexpected credential type %v, expected \"public-key\"", resp["type"])
	}
	return nil
}

// verifiableFormats are the attestation formats simplewebauthn verifies (besides none).
var verifiableFormats = []string{"fido-u2f", "packed", "android-safetynet", "android-key", "tpm", "apple"}

// VerifyRegistrationResponse is verifyRegistrationResponse. Errors correspond to thrown
// errors upstream; Verified=false to a failed attestation statement check.
func VerifyRegistrationResponse(in VerifyRegistrationInput) (*VerifiedRegistrationResponse, error) {
	resp, ok := in.Response.(map[string]any)
	if !ok {
		return nil, errors.New("Invalid registration response")
	}
	if err := checkCredentialEnvelope(resp); err != nil {
		return nil, err
	}
	att, ok := resp["response"].(map[string]any)
	if !ok {
		return nil, errors.New("Credential missing response")
	}
	cd, rawClientData, err := decodeClientData(att["clientDataJSON"])
	if err != nil {
		return nil, err
	}
	if cd.typ != "webauthn.create" {
		return nil, fmt.Errorf("Unexpected registration response type: %s", cd.typ)
	}
	if cd.challenge != in.ExpectedChallenge {
		return nil, fmt.Errorf("Unexpected registration response challenge %q, expected %q", cd.challenge, in.ExpectedChallenge)
	}
	if !slices.Contains(in.ExpectedOrigin, cd.origin) {
		return nil, fmt.Errorf("Unexpected registration response origin %q, expected %q", cd.origin, strings.Join(in.ExpectedOrigin, ", "))
	}
	if err := checkTokenBinding(cd.tokenBinding, "present", "supported", "not-supported"); err != nil {
		return nil, err
	}
	attStr, ok := att["attestationObject"].(string)
	if !ok {
		return nil, errors.New("attestationObject was not a string")
	}
	attBytes, err := fromB64URL(attStr)
	if err != nil {
		return nil, err
	}
	var obj protocol.AttestationObject
	if err := webauthncbor.Unmarshal(attBytes, &obj); err != nil {
		return nil, err
	}
	pad, err := parseAuthenticatorData(obj.RawAuthData)
	if err != nil {
		return nil, err
	}
	matched := ""
	if len(in.ExpectedRPID) > 0 {
		if matched, err = matchRPID(pad.rpIDHash, in.ExpectedRPID); err != nil {
			return nil, err
		}
	}
	if !in.SkipUserPresence && !pad.flags.up {
		return nil, errors.New("User presence was required, but user was not present")
	}
	if in.RequireUserVerification && !pad.flags.uv {
		return nil, errors.New("User verification was required, but user could not be verified")
	}
	if len(pad.credentialID) == 0 {
		return nil, errors.New("No credential ID was provided by authenticator")
	}
	if len(pad.credentialPublicKey) == 0 {
		return nil, errors.New("No public key was provided by authenticator")
	}
	if len(pad.aaguid) == 0 {
		return nil, errors.New("No AAGUID was present during registration")
	}
	var pk webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(pad.credentialPublicKey, &pk); err != nil {
		return nil, err
	}
	if !slices.Contains(SupportedCOSEAlgorithmIdentifiers, pk.Algorithm) {
		return nil, fmt.Errorf("Unexpected public key alg %q", fmt.Sprint(pk.Algorithm))
	}
	clientDataHash := sha256.Sum256(rawClientData)
	switch {
	case obj.Format == "none":
		if len(obj.AttStatement) > 0 {
			return nil, errors.New("None attestation had unexpected attestation statement")
		}
	case slices.Contains(verifiableFormats, obj.Format):
		if err := obj.AuthData.Unmarshal(obj.RawAuthData); err != nil {
			return nil, err
		}
		if err := obj.VerifyAttestation(clientDataHash[:], nil, protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
			return &VerifiedRegistrationResponse{Verified: false}, nil
		}
	default:
		return nil, fmt.Errorf("Unsupported Attestation Format: %s", obj.Format)
	}
	deviceType, backedUp, err := backupFlags(pad.flags)
	if err != nil {
		return nil, err
	}
	var transports []string
	if ts, ok := att["transports"].([]any); ok {
		for _, t := range ts {
			s, _ := t.(string)
			transports = append(transports, s)
		}
	}
	credType, _ := resp["type"].(string)
	return &VerifiedRegistrationResponse{
		Verified: true,
		RegistrationInfo: &RegistrationInfo{
			Fmt:            obj.Format,
			AAGUID:         aaguidString(pad.aaguid),
			CredentialType: credType,
			Credential: RegistrationCredential{
				ID:         b64url(pad.credentialID),
				PublicKey:  pad.credentialPublicKey,
				Counter:    pad.counter,
				Transports: transports,
			},
			AttestationObject:             attBytes,
			UserVerified:                  pad.flags.uv,
			CredentialDeviceType:          deviceType,
			CredentialBackedUp:            backedUp,
			Origin:                        cd.origin,
			RPID:                          matched,
			AuthenticatorExtensionResults: pad.extensions,
		},
	}, nil
}

// VerifyAuthenticationResponse is verifyAuthenticationResponse.
func VerifyAuthenticationResponse(in VerifyAuthenticationInput) (*VerifiedAuthenticationResponse, error) {
	resp, ok := in.Response.(map[string]any)
	if !ok {
		return nil, errors.New("Invalid authentication response")
	}
	if err := checkCredentialEnvelope(resp); err != nil {
		return nil, err
	}
	ar, ok := resp["response"].(map[string]any)
	if !ok {
		return nil, errors.New("Credential missing response")
	}
	cd, rawClientData, err := decodeClientData(ar["clientDataJSON"])
	if err != nil {
		return nil, fmt.Errorf("Credential response clientDataJSON was not a string: %w", err)
	}
	if cd.typ != "webauthn.get" {
		return nil, fmt.Errorf("Unexpected authentication response type: %s", cd.typ)
	}
	if cd.challenge != in.ExpectedChallenge {
		return nil, fmt.Errorf("Unexpected authentication response challenge %q, expected %q", cd.challenge, in.ExpectedChallenge)
	}
	if !slices.Contains(in.ExpectedOrigin, cd.origin) {
		return nil, fmt.Errorf("Unexpected authentication response origin %q, expected %q", cd.origin, strings.Join(in.ExpectedOrigin, ", "))
	}
	authDataStr, ok := ar["authenticatorData"].(string)
	if !ok || !isBase64URL(authDataStr) {
		return nil, errors.New("Credential response authenticatorData was not a base64url string")
	}
	sigStr, ok := ar["signature"].(string)
	if !ok || !isBase64URL(sigStr) {
		return nil, errors.New("Credential response signature was not a base64url string")
	}
	if uh := ar["userHandle"]; jsTruthy(uh) {
		if _, ok := uh.(string); !ok {
			return nil, errors.New("Credential response userHandle was not a string")
		}
	}
	if err := checkTokenBinding(cd.tokenBinding, "present", "supported", "notSupported"); err != nil {
		return nil, err
	}
	authData, err := fromB64URL(authDataStr)
	if err != nil {
		return nil, err
	}
	pad, err := parseAuthenticatorData(authData)
	if err != nil {
		return nil, err
	}
	matched, err := matchRPID(pad.rpIDHash, in.ExpectedRPID)
	if err != nil {
		return nil, err
	}
	if !pad.flags.up {
		return nil, errors.New("User not present during authentication")
	}
	if in.RequireUserVerification && !pad.flags.uv {
		return nil, errors.New("User verification required, but user could not be verified")
	}
	clientDataHash := sha256.Sum256(rawClientData)
	signatureBase := append(append([]byte(nil), authData...), clientDataHash[:]...)
	sig, err := fromB64URL(sigStr)
	if err != nil {
		return nil, err
	}
	if (pad.counter > 0 || in.Credential.Counter > 0) && pad.counter <= in.Credential.Counter {
		return nil, fmt.Errorf("Response counter value %d was lower than expected %d", pad.counter, in.Credential.Counter)
	}
	deviceType, backedUp, err := backupFlags(pad.flags)
	if err != nil {
		return nil, err
	}
	key, err := webauthncose.ParsePublicKey(in.Credential.PublicKey)
	if err != nil {
		return nil, err
	}
	verified, err := webauthncose.VerifySignature(key, signatureBase, sig)
	if err != nil {
		if errors.Is(err, webauthncose.ErrUnsupportedAlgorithm) || errors.Is(err, webauthncose.ErrUnsupportedKey) {
			return nil, err
		}
		verified = false
	}
	return &VerifiedAuthenticationResponse{
		Verified: verified,
		AuthenticationInfo: AuthenticationInfo{
			NewCounter:                    pad.counter,
			CredentialID:                  in.Credential.ID,
			UserVerified:                  pad.flags.uv,
			CredentialDeviceType:          deviceType,
			CredentialBackedUp:            backedUp,
			AuthenticatorExtensionResults: pad.extensions,
			Origin:                        cd.origin,
			RPID:                          matched,
		},
	}, nil
}
