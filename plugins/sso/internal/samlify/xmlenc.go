package samlify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // tripledes-cbc interop
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // rsa-oaep-mgf1p uses SHA-1
	"encoding/base64"
	"errors"
	"strings"

	"github.com/beevik/etree"
)

// XML Encryption algorithm URIs supported by @authenio/xml-encryption.
const (
	EncAES128CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES256CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	EncTripleDESCBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	EncAES128GCM    = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES256GCM    = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	KeyEncRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyEncRSA15     = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
)

// DecryptEncryptedData decrypts an xenc:EncryptedData document/fragment with an RSA private
// key and returns the plaintext (xmlenc.decrypt).
func DecryptEncryptedData(xmlStr string, key *rsa.PrivateKey) (string, error) {
	doc, err := ParseDocument(xmlStr)
	if err != nil {
		return "", err
	}
	all := append([]*etree.Element{doc.Root()}, Descendants(doc.Root())...)
	var keyMethod, keyCipher, dataMethod, dataCipher *etree.Element
	var keyInfo *etree.Element
	for _, e := range all {
		if e.Tag == "KeyInfo" && e.NamespaceURI() == NamespaceDSig && keyInfo == nil {
			keyInfo = e
		}
	}
	for _, e := range all {
		if e.Tag == "KeyInfo" {
			for _, ek := range e.ChildElements() {
				if ek.Tag != "EncryptedKey" {
					continue
				}
				for _, m := range ek.ChildElements() {
					if m.Tag == "EncryptionMethod" && keyMethod == nil {
						keyMethod = m
					}
				}
			}
		}
		if e.Tag == "EncryptedData" {
			for _, c := range e.ChildElements() {
				if c.Tag == "EncryptionMethod" && dataMethod == nil {
					dataMethod = c
				}
				if c.Tag == "CipherData" && dataCipher == nil {
					for _, v := range c.ChildElements() {
						if v.Tag == "CipherValue" {
							dataCipher = v
							break
						}
					}
				}
			}
		}
	}
	if keyMethod == nil {
		return "", errors.New("cant find encryption algorithm")
	}
	if keyInfo != nil {
		for _, d := range Descendants(keyInfo) {
			if d.Tag == "CipherValue" {
				keyCipher = d
				break
			}
		}
	}
	if keyCipher == nil {
		return "", errors.New("cant find encrypted key")
	}
	encKey := Base64Decode(TextContent(keyCipher))
	var symmetric []byte
	alg, _ := AttrValue(keyMethod, "Algorithm")
	switch alg {
	case KeyEncRSAOAEP:
		symmetric, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, key, encKey, nil) //nolint:gosec
	case KeyEncRSA15:
		symmetric, err = rsa.DecryptPKCS1v15(rand.Reader, key, encKey) //nolint:staticcheck
	default:
		return "", errors.New("key encryption algorithm " + alg + " not supported")
	}
	if err != nil {
		return "", err
	}
	if dataMethod == nil || dataCipher == nil {
		return "", errors.New("missing encrypted data")
	}
	content := Base64Decode(TextContent(dataCipher))
	dataAlg, _ := AttrValue(dataMethod, "Algorithm")
	switch dataAlg {
	case EncAES128CBC, EncAES256CBC:
		block, err := aes.NewCipher(symmetric)
		if err != nil {
			return "", err
		}
		return cbcDecrypt(block, content)
	case EncTripleDESCBC:
		block, err := des.NewTripleDESCipher(symmetric)
		if err != nil {
			return "", err
		}
		return cbcDecrypt(block, content)
	case EncAES128GCM, EncAES256GCM:
		block, err := aes.NewCipher(symmetric)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		if len(content) < 12+16 {
			return "", errors.New("invalid ciphertext")
		}
		out, err := gcm.Open(nil, content[:12], content[12:], nil)
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
	return "", errors.New("encryption algorithm " + dataAlg + " not supported")
}

func cbcDecrypt(block cipher.Block, content []byte) (string, error) {
	bs := block.BlockSize()
	if len(content) < bs*2 || (len(content)-bs)%bs != 0 {
		return "", errors.New("invalid ciphertext")
	}
	iv, data := content[:bs], append([]byte(nil), content[bs:]...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	pad := int(data[len(data)-1])
	if pad < 1 || pad > bs {
		return "", errors.New("padding length invalid")
	}
	return string(data[:len(data)-pad]), nil
}

// EncryptOptions configure EncryptContent.
type EncryptOptions struct {
	// CertPEM is the recipient encryption certificate.
	CertPEM                 string
	EncryptionAlgorithm     string
	KeyEncryptionAlgorithm  string
	DisallowInsecureFixture bool
}

// EncryptContent encrypts content into an xenc:EncryptedData element (xmlenc.encrypt).
func EncryptContent(content string, o EncryptOptions) (string, error) {
	cert, err := ParseCertificate(o.CertPEM)
	if err != nil {
		return "", err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("encryption certificate must hold an RSA key")
	}
	alg := o.EncryptionAlgorithm
	if alg == "" {
		alg = EncAES256CBC
	}
	keyAlg := o.KeyEncryptionAlgorithm
	if keyAlg == "" {
		keyAlg = KeyEncRSAOAEP
	}
	keyLen := 32
	switch alg {
	case EncAES128CBC, EncAES128GCM:
		keyLen = 16
	case EncTripleDESCBC:
		keyLen = 24
	}
	symmetric := make([]byte, keyLen)
	_, _ = rand.Read(symmetric)
	var encrypted []byte
	switch alg {
	case EncAES128CBC, EncAES256CBC, EncTripleDESCBC:
		var block cipher.Block
		if alg == EncTripleDESCBC {
			block, err = des.NewTripleDESCipher(symmetric)
		} else {
			block, err = aes.NewCipher(symmetric)
		}
		if err != nil {
			return "", err
		}
		bs := block.BlockSize()
		pad := bs - len(content)%bs
		data := append([]byte(content), make([]byte, pad)...)
		for i := len(content); i < len(data); i++ {
			data[i] = byte(pad)
		}
		iv := make([]byte, bs)
		_, _ = rand.Read(iv)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
		encrypted = append(iv, data...)
	case EncAES128GCM, EncAES256GCM:
		block, err := aes.NewCipher(symmetric)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		iv := make([]byte, 12)
		_, _ = rand.Read(iv)
		encrypted = append(iv, gcm.Seal(nil, iv, []byte(content), nil)...)
	default:
		return "", errors.New("encryption algorithm not supported")
	}
	var encKey []byte
	switch keyAlg {
	case KeyEncRSAOAEP:
		encKey, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, symmetric, nil) //nolint:gosec
	case KeyEncRSA15:
		encKey, err = rsa.EncryptPKCS1v15(rand.Reader, pub, symmetric) //nolint:staticcheck
	default:
		return "", errors.New("encryption key algorithm not supported")
	}
	if err != nil {
		return "", err
	}
	certB64 := NormalizeCerString(o.CertPEM)
	var b strings.Builder
	b.WriteString(`<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">`)
	b.WriteString(`<xenc:EncryptionMethod Algorithm="` + alg + `" />`)
	b.WriteString(`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">`)
	b.WriteString(`<e:EncryptionMethod Algorithm="` + keyAlg + `"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /></e:EncryptionMethod>`)
	b.WriteString(`<KeyInfo><X509Data><X509Certificate>` + certB64 + `</X509Certificate></X509Data></KeyInfo>`)
	b.WriteString(`<e:CipherData><e:CipherValue>` + base64.StdEncoding.EncodeToString(encKey) + `</e:CipherValue></e:CipherData>`)
	b.WriteString(`</e:EncryptedKey></KeyInfo>`)
	b.WriteString(`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(encrypted) + `</xenc:CipherValue></xenc:CipherData>`)
	b.WriteString(`</xenc:EncryptedData>`)
	return b.String(), nil
}

// DecryptAssertion replaces the single /Response/EncryptedAssertion of xmlStr with its
// decrypted assertion and returns the new document and the assertion XML
// (libsaml.decryptAssertion).
func DecryptAssertion(sp *Entity, xmlStr string) (string, string, error) {
	if xmlStr == "" {
		return "", "", errors.New("ERR_UNDEFINED_ASSERTION")
	}
	doc, err := ParseDocument(xmlStr)
	if err != nil {
		return "", "", err
	}
	root := doc.Root()
	if !strings.Contains(root.Tag, "Response") {
		return "", "", errors.New("ERR_UNDEFINED_ENCRYPTED_ASSERTION")
	}
	var encs []*etree.Element
	for _, c := range root.ChildElements() {
		if c.Tag == "EncryptedAssertion" {
			encs = append(encs, c)
		}
	}
	if len(encs) == 0 {
		return "", "", errors.New("ERR_UNDEFINED_ENCRYPTED_ASSERTION")
	}
	if len(encs) > 1 {
		return "", "", errors.New("ERR_MULTIPLE_ASSERTION")
	}
	if sp.Setting.EncPrivateKey == "" {
		return "", "", errors.New("ERR_EXCEPTION_OF_ASSERTION_DECRYPTION")
	}
	signer, err := ParsePrivateKey(sp.Setting.EncPrivateKey, sp.Setting.EncPrivateKeyPass)
	if err != nil {
		return "", "", err
	}
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return "", "", errors.New("decryption requires an RSA key")
	}
	plain, err := DecryptEncryptedData(ElementString(encs[0]), key)
	if err != nil {
		return "", "", errors.New("ERR_EXCEPTION_OF_ASSERTION_DECRYPTION")
	}
	adoc, err := ParseDocument(plain)
	if err != nil {
		return "", "", err
	}
	idx := encs[0].Index()
	root.RemoveChildAt(idx)
	root.InsertChildAt(idx, adoc.Root())
	return DocumentString(doc), plain, nil
}

// EncryptAssertion replaces the single assertion of xmlStr with an EncryptedAssertion
// for the target's encryption certificate and returns the base64 document
// (libsaml.encryptAssertion; used by identity-provider helpers).
func EncryptAssertion(source *Entity, target *Entity, xmlStr string) (string, error) {
	doc, err := ParseDocument(xmlStr)
	if err != nil {
		return "", err
	}
	var assertions []*etree.Element
	for _, d := range append([]*etree.Element{doc.Root()}, Descendants(doc.Root())...) {
		if d.Tag == "Assertion" {
			assertions = append(assertions, d)
		}
	}
	if len(assertions) == 0 {
		return "", errors.New("ERR_NO_ASSERTION")
	}
	if len(assertions) > 1 {
		return "", errors.New("ERR_MULTIPLE_ASSERTION")
	}
	if !source.Setting.IsAssertionEncrypted {
		return Base64Encode(xmlStr), nil
	}
	certs := target.Meta.GetX509Certificates("encryption")
	if len(certs) == 0 {
		return "", errors.New("ERR_EXCEPTION_OF_ASSERTION_ENCRYPTION")
	}
	enc, err := EncryptContent(ElementString(assertions[0]), EncryptOptions{
		CertPEM:                certs[0],
		EncryptionAlgorithm:    source.Setting.DataEncryptionAlgorithm,
		KeyEncryptionAlgorithm: source.Setting.KeyEncryptionAlgorithm,
	})
	if err != nil {
		return "", err
	}
	wrapper, err := ParseDocument(`<saml:EncryptedAssertion xmlns:saml="` + NamespaceAssertion + `">` + enc + `</saml:EncryptedAssertion>`)
	if err != nil {
		return "", err
	}
	parent := assertions[0].Parent()
	idx := assertions[0].Index()
	parent.RemoveChildAt(idx)
	parent.InsertChildAt(idx, wrapper.Root())
	return Base64Encode(DocumentString(doc)), nil
}
