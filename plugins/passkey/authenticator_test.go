package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// softAuthenticator is a software WebAuthn authenticator (ES256) used to drive real
// registration and authentication ceremonies in tests.
type softAuthenticator struct {
	t           *testing.T
	key         *ecdsa.PrivateKey
	credID      []byte
	aaguid      []byte
	counter     uint32
	origin      string
	attestation string // "none" or "packed" (self attestation)
	// flags: UP|UV by default; set backup bits through be/bs.
	uv, be, bs bool
	userHandle string
	corruptSig bool
}

func newSoftAuthenticator(t *testing.T, origin, attestation string) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	aaguid := make([]byte, 16)
	copy(aaguid, []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4})
	return &softAuthenticator{t: t, key: key, credID: id, aaguid: aaguid, origin: origin, attestation: attestation, uv: true}
}

func (a *softAuthenticator) credentialID() string { return b64url(a.credID) }

// coseKey is the COSE_Key of the credential public key (EC2, P-256, ES256).
func (a *softAuthenticator) coseKey() []byte {
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	b, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

func (a *softAuthenticator) flags(attested bool) byte {
	f := byte(1) // UP
	if a.uv {
		f |= 1 << 2
	}
	if a.be {
		f |= 1 << 3
	}
	if a.bs {
		f |= 1 << 4
	}
	if attested {
		f |= 1 << 6
	}
	return f
}

func (a *softAuthenticator) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, a.flags(attested))
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, a.counter)
	out = append(out, c...)
	if attested {
		out = append(out, a.aaguid...)
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(a.credID)))
		out = append(out, l...)
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

func (a *softAuthenticator) sign(data []byte) []byte {
	h := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, h[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return sig
}

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

// register answers PublicKeyCredentialCreationOptionsJSON with RegistrationResponseJSON.
func (a *softAuthenticator) register(options map[string]any) map[string]any {
	a.t.Helper()
	rp, _ := options["rp"].(map[string]any)
	rpID, _ := rp["id"].(string)
	user, _ := options["user"].(map[string]any)
	a.userHandle, _ = user["id"].(string)
	challenge, _ := options["challenge"].(string)
	cd := a.clientData("webauthn.create", challenge)
	authData := a.authData(rpID, true)
	attStmt := map[string]any{}
	if a.attestation == "packed" {
		h := sha256.Sum256(cd)
		sig := a.sign(append(append([]byte(nil), authData...), h[:]...))
		if a.corruptSig {
			sig = a.sign([]byte("something else"))
		}
		attStmt = map[string]any{"alg": -7, "sig": sig}
	}
	att, err := webauthncbor.Marshal(map[string]any{"fmt": a.attestation, "attStmt": attStmt, "authData": authData})
	if err != nil {
		a.t.Fatal(err)
	}
	return map[string]any{
		"id":    a.credentialID(),
		"rawId": a.credentialID(),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":     b64url(cd),
			"attestationObject":  b64url(att),
			"transports":         []any{"internal", "hybrid"},
			"publicKeyAlgorithm": -7,
		},
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
		"authenticatorAttachment": "platform",
	}
}

// authenticate answers PublicKeyCredentialRequestOptionsJSON with AuthenticationResponseJSON.
func (a *softAuthenticator) authenticate(options map[string]any) map[string]any {
	a.t.Helper()
	rpID, _ := options["rpId"].(string)
	challenge, _ := options["challenge"].(string)
	a.counter++
	cd := a.clientData("webauthn.get", challenge)
	authData := a.authData(rpID, false)
	h := sha256.Sum256(cd)
	sig := a.sign(append(append([]byte(nil), authData...), h[:]...))
	return map[string]any{
		"id":    a.credentialID(),
		"rawId": a.credentialID(),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url(cd),
			"authenticatorData": b64url(authData),
			"signature":         b64url(sig),
			"userHandle":        a.userHandle,
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	}
}
