package samlify

import (
	"strings"
	"testing"
	"time"
)

func mustIdP(t *testing.T, encrypted bool) *Entity {
	t.Helper()
	idp, err := IdentityProvider(Setting{Metadata: idpMetadata, PrivateKey: idPk, PrivateKeyPass: "jXmKf9By6ruLnUdRo90G", IsAssertionEncrypted: encrypted,
		LoginResponseTemplate: &LoginResponseTemplate{Context: strings.Replace(DefaultLoginResponseTemplate, "{AuthnStatement}", "", 1), Attributes: []TemplateAttribute{
			{Name: "email", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", ValueTag: "email", ValueXsiType: "xs:string"},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	return idp
}

func TestRoundTrip(t *testing.T) {
	for _, enc := range []bool{false, true} {
		idp := mustIdP(t, enc)
		sp, err := ServiceProvider(Setting{EntityID: "http://localhost:3001/api/sso/saml2/sp/metadata", EncryptCert: []string{certificate}, EncPrivateKey: idpPrivateKey, EncPrivateKeyPass: "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW",
			AssertionConsumerService: []Service{{Binding: BindingPostURN, Location: "http://localhost:3001/api/sso/saml2/sp/acs"}}})
		if err != nil {
			t.Fatal(err)
		}
		_, resp, err := idp.CreateLoginResponse(sp, "", LoginResponseUser{Email: "a@b.com"}, func(tpl string) (string, string) {
			now := time.Now()
			return "_x", ReplaceTagsByValue(tpl, []Tag{T("ID", "_resp"), T("AssertionID", "_assert"), T("Destination", "http://localhost:3001/api/sso/saml2/sp/acs"),
				T("Audience", sp.Meta.GetEntityID()), T("SubjectRecipient", "http://localhost:3001/api/sso/saml2/sp/acs"), T("Issuer", idp.Meta.GetEntityID()),
				T("IssueInstant", ISOTime(now)), T("StatusCode", StatusSuccess), T("ConditionsNotBefore", ISOTime(now)), T("ConditionsNotOnOrAfter", ISOTime(now.Add(time.Minute))),
				T("SubjectConfirmationDataNotOnOrAfter", ISOTime(now.Add(time.Minute))), T("NameIDFormat", NameIDFormatEmailAddress), T("NameID", "a@b.com"), T("InResponseTo", "null"),
				T("attrEmail", "a@b.com")})
		})
		if err != nil {
			t.Fatal(err)
		}
		res, err := sp.ParseLoginResponse(idp, resp)
		if err != nil {
			t.Fatalf("enc=%v: %v", enc, err)
		}
		if res.Extract.NameID.Value != "a@b.com" || res.Extract.Attributes["email"] != "a@b.com" {
			t.Fatalf("bad extract %+v", res.Extract)
		}
	}
}
