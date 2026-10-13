package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/plugins/siwe"
)

// SIWE profile (mirrors e2e/servers/profiles/siwe.mjs). verifyMessage performs real
// EIP-191 personal_sign verification: the secp256k1 public key is recovered from the
// 65-byte signature (implemented below with math/big, as no secp256k1 library is a
// dependency) and its address compared with the message address.
func init() {
	profiles["siwe"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Database = pluginSQLite()
		cfg.Plugins = append(cfg.Plugins, siwe.New(siwe.Options{
			Domain: "example.com",
			GetNonce: func(context.Context) (string, error) {
				return bacrypto.RandomString(32, "a-z", "A-Z", "0-9"), nil
			},
			VerifyMessage: func(_ context.Context, a siwe.VerifyMessageArgs) (bool, error) {
				addr, ok := recoverEIP191(a.Message, a.Signature)
				return ok && strings.EqualFold(addr, a.Address), nil
			},
		}))
	}
}

var (
	secpP, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpGx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

type ecPoint struct{ x, y *big.Int } // nil x = point at infinity

func modP(v *big.Int) *big.Int { return new(big.Int).Mod(v, secpP) }

func ecAdd(a, b ecPoint) ecPoint {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	var l *big.Int
	if a.x.Cmp(b.x) == 0 {
		if modP(new(big.Int).Add(a.y, b.y)).Sign() == 0 {
			return ecPoint{}
		}
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		den := new(big.Int).ModInverse(modP(new(big.Int).Mul(big.NewInt(2), a.y)), secpP)
		l = modP(num.Mul(num, den))
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).ModInverse(modP(new(big.Int).Sub(b.x, a.x)), secpP)
		l = modP(num.Mul(num, den))
	}
	x := modP(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(l, l), a.x), b.x))
	y := modP(new(big.Int).Sub(new(big.Int).Mul(l, new(big.Int).Sub(a.x, x)), a.y))
	return ecPoint{x, y}
}

func ecMul(k *big.Int, p ecPoint) ecPoint {
	r := ecPoint{}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = ecAdd(r, r)
		if k.Bit(i) == 1 {
			r = ecAdd(r, p)
		}
	}
	return r
}

func keccak(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// recoverEIP191 returns the 0x-prefixed address that produced a personal_sign signature.
func recoverEIP191(message, signature string) (string, bool) {
	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil || len(sig) != 65 {
		return "", false
	}
	v := int(sig[64])
	if v >= 27 {
		v -= 27
	}
	if v != 0 && v != 1 {
		return "", false
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Cmp(secpN) >= 0 {
		return "", false
	}
	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message))
	e := new(big.Int).SetBytes(keccak([]byte(prefix + message)))
	// R = (r, y) with y of parity v
	y2 := modP(new(big.Int).Add(new(big.Int).Exp(r, big.NewInt(3), secpP), big.NewInt(7)))
	y := new(big.Int).Exp(y2, new(big.Int).Rsh(new(big.Int).Add(secpP, big.NewInt(1)), 2), secpP)
	if modP(new(big.Int).Mul(y, y)).Cmp(y2) != 0 {
		return "", false
	}
	if int(y.Bit(0)) != v {
		y.Sub(secpP, y)
	}
	rInv := new(big.Int).ModInverse(r, secpN)
	u1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Neg(e), rInv), secpN)
	u2 := new(big.Int).Mod(new(big.Int).Mul(s, rInv), secpN)
	q := ecAdd(ecMul(u1, ecPoint{secpGx, secpGy}), ecMul(u2, ecPoint{r, y}))
	if q.x == nil {
		return "", false
	}
	pub := make([]byte, 64)
	q.x.FillBytes(pub[:32])
	q.y.FillBytes(pub[32:])
	return "0x" + hex.EncodeToString(keccak(pub)[12:]), true
}
