package siwe

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ParsedMessage is the subset of an EIP-4361 message the plugin inspects
// (ParsedSiweMessage). Empty strings mean the field is absent; HasChainID reports whether
// a numeric "Chain ID" line was found.
type ParsedMessage struct {
	Scheme         string
	Domain         string
	Address        string
	URI            string
	Version        string
	ChainID        float64
	HasChainID     bool
	Nonce          string
	HasNonce       bool
	IssuedAt       string
	ExpirationTime string
	NotBefore      string
	RequestID      string
}

var (
	headerRe  = regexp.MustCompile(`^(?:([a-zA-Z][a-zA-Z0-9+.-]*)://)?(\S+) wants you to sign in with your Ethereum account:$`)
	addressRe = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	// JavaScript's "." does not match line terminators.
	fieldRe     = regexp.MustCompile(`^([A-Za-z ]+): ([^\r\n\x{2028}\x{2029}]*)$`)
	lineSplitRe = regexp.MustCompile(`\r?\n`)
	schemeRe    = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)
)

// jsNumber mirrors JavaScript's Number(string) for decimal, hex, octal and binary literals.
func jsNumber(v string) float64 {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0
	}
	if strings.ContainsRune(s, '_') {
		return math.NaN()
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "0x") || strings.HasPrefix(lower, "0o") || strings.HasPrefix(lower, "0b") {
		if i, err := strconv.ParseUint(s[2:], map[byte]int{'x': 16, 'o': 8, 'b': 2}[lower[1]], 64); err == nil {
			return float64(i)
		}
		return math.NaN()
	}
	switch s {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if strings.ContainsAny(lower, "infa") {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return f
}

// ParseMessage parses an EIP-4361 message like parseSiweMessage upstream.
func ParseMessage(message string) ParsedMessage {
	var r ParsedMessage
	lines := lineSplitRe.Split(message, -1)
	if len(lines) > 0 {
		if m := headerRe.FindStringSubmatch(lines[0]); m != nil {
			r.Scheme = m[1]
			r.Domain = m[2]
		}
	}
	if len(lines) > 1 {
		if a := strings.TrimSpace(lines[1]); a != "" && addressRe.MatchString(a) {
			r.Address = a
		}
	}
	for _, line := range lines {
		m := fieldRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, value := m[1], m[2]
		switch key {
		case "URI":
			r.URI = value
		case "Version":
			r.Version = value
		case "Chain ID":
			n := jsNumber(value)
			if !math.IsNaN(n) && !math.IsInf(n, 0) && n == math.Trunc(n) {
				r.ChainID, r.HasChainID = n, true
			}
		case "Nonce":
			r.Nonce, r.HasNonce = value, true
		case "Issued At":
			r.IssuedAt = value
		case "Expiration Time":
			r.ExpirationTime = value
		case "Not Before":
			r.NotBefore = value
		case "Request ID":
			r.RequestID = value
		}
	}
	return r
}

// NormalizeDomain lower-cases a domain and strips any scheme and path (normalizeSiweDomain).
func NormalizeDomain(domain string) string {
	s := schemeRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(domain)), "")
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i]
	}
	return s
}

// ToChecksumAddress returns the EIP-55 checksummed form of an address (toChecksumAddress).
func ToChecksumAddress(address string) string {
	address = strings.Replace(strings.ToLower(address), "0x", "", 1)
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(address))
	sum := h.Sum(nil)
	const hexdigits = "0123456789abcdef"
	hexHash := make([]byte, 0, 64)
	for _, b := range sum {
		hexHash = append(hexHash, hexdigits[b>>4], hexdigits[b&0xf])
	}
	var b strings.Builder
	b.WriteString("0x")
	for i := 0; i < 40 && i < len(address); i++ {
		c := address[i]
		nibble := hexHash[i]
		v := int(nibble - '0')
		if nibble >= 'a' {
			v = int(nibble-'a') + 10
		}
		if v >= 8 {
			b.WriteString(strings.ToUpper(string(c)))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
