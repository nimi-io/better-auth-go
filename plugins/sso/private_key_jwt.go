package sso

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// PrivateKeyJWTSigningAlgorithms are the supported private_key_jwt algorithms.
var PrivateKeyJWTSigningAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

func resolvePrivateKeyJWTAlgorithm(k *PrivateKey, algorithm string) (string, error) {
	if k.PrivateKeyJWK == nil && k.PrivateKeyPEM == "" {
		return "", errors.New("private_key_jwt requires either privateKeyJwk or privateKeyPem")
	}
	unsupported := func(a string) error {
		return fmt.Errorf("Unsupported private_key_jwt signing algorithm: %s. Use one of %s.", a, strings.Join(PrivateKeyJWTSigningAlgorithms, ", "))
	}
	if algorithm != "" && !inList(PrivateKeyJWTSigningAlgorithms, algorithm) {
		return "", unsupported(algorithm)
	}
	jwkAlg, _ := k.PrivateKeyJWK["alg"].(string)
	if jwkAlg != "" && !inList(PrivateKeyJWTSigningAlgorithms, jwkAlg) {
		return "", unsupported(jwkAlg)
	}
	if algorithm != "" && jwkAlg != "" && algorithm != jwkAlg {
		return "", fmt.Errorf("JWK alg %q does not match configured algorithm %q. Remove the JWK alg field, or pass an algorithm that matches the JWK.", jwkAlg, algorithm)
	}
	if algorithm != "" {
		return algorithm, nil
	}
	if jwkAlg != "" {
		return jwkAlg, nil
	}
	return "RS256", nil
}

// privateKeyJWTAssertionGetter returns a client assertion signer
// (createPrivateKeyJwtClientAssertionGetter).
func privateKeyJWTAssertionGetter(k *PrivateKey, kid, algorithm string) (func(clientID, tokenEndpoint, grantType string) (string, error), error) {
	alg, err := resolvePrivateKeyJWTAlgorithm(k, algorithm)
	if err != nil {
		return nil, err
	}
	var key any
	if k.PrivateKeyJWK != nil {
		b, err := json.Marshal(k.PrivateKeyJWK)
		if err != nil {
			return nil, err
		}
		var j jose.JWK
		if err := json.Unmarshal(b, &j); err != nil {
			return nil, err
		}
		if key, err = j.PrivateKey(); err != nil {
			return nil, err
		}
		if kid == "" {
			kid, _ = k.PrivateKeyJWK["kid"].(string)
		}
	} else {
		block, _ := pem.Decode([]byte(k.PrivateKeyPEM))
		if block == nil {
			return nil, errors.New("invalid privateKeyPem")
		}
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}
	return func(clientID, tokenEndpoint, _ string) (string, error) {
		now := time.Now().Unix()
		h := jsonx.O("alg", alg, "typ", "JWT")
		if kid != "" {
			h.Set("kid", kid)
		}
		p := jsonx.O("iss", clientID, "sub", clientID, "aud", tokenEndpoint, "iat", float64(now), "exp", float64(now+120), "jti", bacrypto.RandomUUID())
		return jose.SignJWT(h, p, key)
	}, nil
}
