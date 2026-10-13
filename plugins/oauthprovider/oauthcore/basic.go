package oauthcore

import (
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Port of packages/core/src/oauth2/basic-credentials.ts and the client-assertion constants.

// ClientAssertionType is the RFC 7523 JWT bearer client assertion type.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// PrivateKeyJWTSigningAlgorithms are the algorithms accepted for private_key_jwt.
var PrivateKeyJWTSigningAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512", "EdDSA"}

var basicRe = regexp.MustCompile(`(?i)^Basic +(.*)$`)

func formURLEncode(s string) string { return formEncode(s) }

func formURLDecode(s string) (string, error) {
	return url.QueryUnescape(s)
}

// EncodeBasicCredentials is encodeBasicCredentials ("Basic base64(id:secret)").
func EncodeBasicCredentials(clientID, clientSecret string) string {
	payload := formURLEncode(clientID) + ":" + formURLEncode(clientSecret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
}

// DecodeBasicCredentials is decodeBasicCredentials.
func DecodeBasicCredentials(authorization string) (clientID, clientSecret string, err error) {
	m := basicRe.FindStringSubmatch(authorization)
	if m == nil {
		return "", "", errors.New("Authorization header is not a Basic credential")
	}
	raw, err := decodeBase64JS(m[1])
	if err != nil {
		return "", "", err
	}
	decoded := strings.ToValidUTF8(string(raw), "�")
	i := strings.Index(decoded, ":")
	if i == -1 {
		return "", "", errors.New("Basic credential is missing the client id/secret separator")
	}
	rawID, rawSecret := decoded[:i], decoded[i+1:]
	if rawID == "" || rawSecret == "" {
		return "", "", errors.New("Basic credential client id and secret must both be non-empty")
	}
	if clientID, err = formURLDecode(rawID); err != nil {
		clientID = rawID
	}
	if clientSecret, err = formURLDecode(rawSecret); err != nil {
		clientSecret = rawSecret
	}
	return clientID, clientSecret, nil
}

// decodeBase64JS decodes like @better-auth/utils base64.decode (padding optional, url-safe
// characters accepted).
func decodeBase64JS(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}
