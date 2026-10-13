// Mock identity provider for the OAuth e2e tests. Both the Go and the TypeScript servers
// rewrite requests for provider hosts (github.com, googleapis.com, ...) to this server as
// http://127.0.0.1:<port>/<original-host>/<original-path>, so the real provider code runs on
// both sides.
//
// Conventions:
//   - the authorization code is "code-<base64url(json profile)>"; the access token echoes it,
//     so user-info endpoints can return that profile.
//   - GET /__idp/id-token?claims=<json> returns an RS256 id token signed by this IdP.
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { inflateRawSync } from "node:zlib";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const port = Number(process.env.PORT || 4900);
const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...(await exportJWK(publicKey)), kid: "e2e-key", alg: "RS256", use: "sig" };

function profileFromToken(token) {
  try {
    return JSON.parse(Buffer.from(String(token).replace(/^(code-|Bearer )/, ""), "base64url").toString());
  } catch {
    return null;
  }
}

async function readBody(req) {
  let body = "";
  for await (const chunk of req) body += chunk;
  return body;
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const path = url.pathname;
  const auth = req.headers.authorization || "";
  if (path === "/__idp/health") return res.end("ok");
  if (path === "/__idp/id-token") {
    const claims = JSON.parse(url.searchParams.get("claims") || "{}");
    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "JWT" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
    return json(res, 200, { token });
  }
  // GitHub
  if (path === "/github.com/login/oauth/access_token" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const code = form.get("code");
    if (!code?.startsWith("code-")) return json(res, 200, { error: "bad_verification_code" });
    return json(res, 200, { access_token: code.slice(5), token_type: "bearer", scope: "read:user,user:email" });
  }
  if (path === "/api.github.com/user") {
    const p = profileFromToken(auth.replace(/^Bearer /i, ""));
    if (!p) return json(res, 401, { message: "Bad credentials" });
    return json(res, 200, { id: p.id, login: p.login ?? "octo", name: p.name ?? null, email: null, avatar_url: p.avatar ?? "https://avatars.example/u.png" });
  }
  if (path === "/api.github.com/user/emails") {
    const p = profileFromToken(auth.replace(/^Bearer /i, ""));
    if (!p) return json(res, 401, { message: "Bad credentials" });
    return json(res, 200, [{ email: p.email, primary: true, verified: p.verified !== false, visibility: "public" }]);
  }
  // Google
  if (path === "/www.googleapis.com/oauth2/v3/certs") return json(res, 200, { keys: [jwk] });
  if (path === "/oauth2.googleapis.com/token" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const p = profileFromToken(form.get("code"));
    if (!p) return json(res, 400, { error: "invalid_grant" });
    const idToken = await new SignJWT({ iss: "https://accounts.google.com", aud: form.get("client_id"), email_verified: true, ...p })
      .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "JWT" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
    return json(res, 200, { access_token: "ya29.e2e", refresh_token: "1//refresh", expires_in: 3599, scope: "openid email profile", token_type: "Bearer", id_token: idToken });
  }
  // Generic OpenID provider (generic-oauth / oauth-popup profiles), served over plain http at
  // /oidc. The code is "code-<base64url(json profile)>"; profile.nonce is echoed in the id
  // token, profile.idTokenClaims are merged into it, the rest is returned by /userinfo.
  if (path.startsWith("/oidc/") || path.startsWith("/oidc-plain/")) {
    const issuer = `http://127.0.0.1:${port}/oidc`;
    if (path === "/oidc/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        end_session_endpoint: `${issuer}/logout`,
        id_token_signing_alg_values_supported: ["RS256"],
        response_types_supported: ["code"],
      });
    }
    if (path === "/oidc/jwks") return json(res, 200, { keys: [jwk] });
    if ((path === "/oidc/token" || path === "/oidc-plain/token") && req.method === "POST") {
      const form = new URLSearchParams(await readBody(req));
      let clientId = form.get("client_id");
      if (auth.startsWith("Basic ")) clientId = decodeURIComponent(Buffer.from(auth.slice(6), "base64").toString().split(":")[0]);
      if (form.get("grant_type") === "refresh_token") {
        return json(res, 200, { access_token: `refreshed-${form.get("refresh_token")}`, refresh_token: "rotated-refresh", expires_in: 3600, token_type: "Bearer", scope: "openid profile" });
      }
      const p = profileFromToken(form.get("code"));
      if (!p) return json(res, 400, { error: "invalid_grant" });
      const out = { access_token: form.get("code").slice(5), refresh_token: "oidc-refresh", expires_in: 3600, token_type: "Bearer", scope: p.scope ?? "openid profile email" };
      if (path === "/oidc/token") {
        out.id_token = await new SignJWT({ iss: issuer, aud: clientId, sub: p.sub ?? "unknown", ...(p.nonce ? { nonce: p.nonce } : {}), ...(p.idTokenClaims ?? {}) })
          .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "JWT" })
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(privateKey);
      }
      return json(res, 200, out);
    }
    if (path === "/oidc/userinfo" || path === "/oidc-plain/userinfo") {
      const p = profileFromToken(auth.replace(/^Bearer /i, ""));
      if (!p) return json(res, 401, { error: "invalid_token" });
      const { nonce, idTokenClaims, scope, ...info } = p;
      return json(res, 200, info);
    }
  }
  // SAML 2.0 identity provider (sso profile), served at /saml. Signs with the upstream
  // @better-auth/sso test fixture key. GET /saml/sso takes the SP's redirect-binding
  // AuthnRequest plus test-only parameters (email, name, signAssertion=1) and returns
  // { SAMLResponse, RelayState, acs } instead of an auto-submitting form;
  // GET /saml/idp-initiated?acs=&audience=&email= returns an unsolicited response.
  if (path.startsWith("/saml/")) {
    const base = `http://127.0.0.1:${port}/saml`;
    const metadata = samlIdpMetadata(base);
    if (path === "/saml/metadata") {
      res.setHeader("content-type", "application/xml");
      return res.end(metadata);
    }
    if (path === "/saml/sso" || path === "/saml/idp-initiated") {
      let id = "", issuer = url.searchParams.get("audience") || "", acs = url.searchParams.get("acs") || "";
      if (path === "/saml/sso") {
        const xml = inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest") || "", "base64")).toString("utf8");
        id = (xml.match(/\sID="([^"]+)"/) || [])[1] || "";
        acs = (xml.match(/AssertionConsumerServiceURL="([^"]+)"/) || [])[1] || acs;
        issuer = (xml.match(/<saml:Issuer>([^<]+)<\/saml:Issuer>/) || [])[1] || issuer;
      }
      const email = url.searchParams.get("email") || "saml-user@example.com";
      const response = await samlLoginResponse({ base, metadata, id, issuer, acs, email, name: url.searchParams.get("name") || "Saml User",
        signAssertion: url.searchParams.get("signAssertion") === "1" });
      return json(res, 200, { SAMLResponse: response, RelayState: url.searchParams.get("RelayState"), acs });
    }
  }
  json(res, 404, { error: "not_found", path });
}).listen(port, "127.0.0.1", () => console.log(`mock idp on http://127.0.0.1:${port}`));

// ---- SAML identity provider helpers ----
const require = createRequire(import.meta.url);
const SAML_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIJKgIBAAKCAgEA+YIi6C8hA+NSB7dEcQf5OseCtL8wCohnnD8nnUTUdaMor9zm
JLhuY4ExNsHD2XO5A9RIOXerYdAVh8v6L2jUuZpIJzleoypDGlluLAjEpy52lstL
Hn7TytzuJjXmaTOXvWpo9oF52byqyvHKpyf27FFEL18bbVzVVZjh1oP7d3NryeF7
lH6YesCCm649veyC87gBUTbwFcXktLRJcHqb2eVm3+x3NTDkQKk6cP5qfHEYx0c2
AgPcujjOIYFbNYL0yUvFhqDJrHQGR2jp7/byyb1t4wy0EHnDoXmCCZ3FoHBEsyRS
JJl2naK2AhH1ocMAXVaYZJ5ni6+ATKSQXJQGGhY2AyyCqTHF2DuZP9q9wYEj5cOK
Km8W0eYHg9OZsimLWf8DVLZLtdfDY4SHyRbpVP5Hw3Kda2GJL84AX6q/NMIDabOK
EM1a9Zp6YB7EkwIVzLmW2kwciUZj6nnMr8kKkUHESDdKEyyTRss6FH9EZB+gyieP
u6g4ZauGYZX7KPThTL/cXjjXyKyaOR7U3xWX4nZF2aoq9masKjZTTjHyuQ7GKt+8
dhpIKooOJ6i6SE18sX50KS9h7GqBa5XLbfzi/mam2uzU+IXmJPRl/KpQEviKbL+k
9h0gDW2oeeaEkt7r3KwzroNmau/hmDCyktSClCocF/sCzMZjMEiUPWYBcH0CAwEA
AQKCAgABJVzdriG7r9aXnHre/gdiArqR8/LXiYrYR935tfA33hj4vc38yzAOmvBL
7RXmMMbfwqDWSrtpxpfiuMgcYaHgfFnqfDP4EeCfBVwhLaUhk3AN/z8IE9MLMnqR
iFvXjdobj5qNz0hs/JXYOsYQgHl82l6yzQAGP4/nRb17y71i7g/HrJZxtyciITI4
XtN/xM9RKT4wTk1J/E+xmMZhkt6WYJxZWO+vOdtChMR08mYwziAsAiK4XaYs4Mfp
lXuCwmg3aHauyJxEg3/n4g55AKxaytjvWwaUsMp6OmGjg6r9sqZOIFOUQXQvAylM
1yJGrOuagiRPCf81wAeZ0oOrOS7R+4fF4Ypa+V7Cp6Ty3VPcw8BFpXJ6fRtf92kh
ix00DnFEK/TdndyBpFKdmf8f2SSFBLrPlmTfjdMAvShE5yFpeWyXQjftI5q/0d3U
Ug0MBby66yT/TZtTKVPdK6bG3fYvzgKCpZGrKgn+umq4XR+gh9S0ptmwNF5mzJy4
mol5CkazGPlOSwlBc4oKeepcqZ0TKCJwonub90CJeH8IKoyRsswShRl6YTRza1SB
Fx4Gis5xcaNp7eXnLBDgKV/1bhCUSvQ886r+Xo4nfhk9n8WrtaQFC4tFID1e8TAM
jYxZIBpCHOZHX/+BpC3FyqD4RbI12iudyz4KwS5Ps/wlIpVMQQKCAQEA/70X3Fz2
SJyPP9UdiiqLot1ppbagQGjG20yFnfRDhNY+q2U8N77yJUXWvE7YQ6OUTOaPuJX2
X7vulTSQ0YyFYp0B5G4QiFtvPOpBvn7OxrFKBKxwbOU7L2rAuXWYEIRuKuwBRMFU
oaar8gkKlnsUtUxrLM827gmL13i3GX2bmm6NhhGCKbSCoD51+UUGo7Ix5ZLznKmX
G1mq4IxtJe8vLk/9RT9CzRV7VO61EgEh7Iji7g4cDIiZV+B9gG8YMlTOcALPpgud
nF7SEvDuMH3dgOj+iSO9piJ53okU59Mk4Nyka3p3v6RABMcDYO1/wkbE83+Oobrx
RiRQHtBgo1r9cQKCAQEA+cNpxVCi/BkatlzKentRabnQjfxrEQdIdc9xqzr5k2xK
w9n+XGzeNT+HKI/S1KkfvJTQC0j9WBQ3uupf8Zg6/mNF84YCXpun3JXpvzc+4ya3
i1AXtdul/JYU5qhMrJI+I1WXrWAls5zbIs23iz1Fq530Mb7FUQ5jmO0p123AmMGG
hSTJDqvKDMpQXdUYQMqrSL/aNh8u7wpw2S052uj2bdbdgq1FboLzbwWTOsVYs3aS
HABb95263Cf3OdRr4lyN6khFMLhQPUhYnn6l2ob0kIZ7V2f8fxKvJoTTDTxWpUgF
FrdHigaDo09WYkIukj+YdSZY/ZEAu7lyMmY0l8HNzQKCAQEA7HE3jlWknp2hE7NG
DGgpkfqDouKmZuZ4dGjbYJ5ljntGldCTTDcOSce4MYH0ERU8F51TY6XCk+B9RRXE
jvkMmY/wH/Ji9q8SuY8cGbPEGY/wj0Ge8A9AGSbp6I4AecT21lg9FARq6sneT3hs
gZRqIPT2YgdzEcFhuWWyY67uHmn4DuxBG634147oI/7dlJs75rVm5oElY/QTOGic
wWXSiU8LKurCKDqkPHI2lt7VLougw9fntu7UV5sGbahJBr/B3W277hjvL5O7Rifb
EJpOINFKBCE3RlK5ujWjTnK4te1JVtVzwYtqZQBa71KlvEkR7s8QYBcm22LXcKXX
szB9AQKCAQEAwUua8DoX6UMEiV4G1gPaXhiQb1KLCgK48XQ6ZGqf/JgyxKBRWvZm
go9H6vxkDnFVPn1tBU7XwvLirqX02uUVwwrReEaeTtnob68V2AbJhMLSCd9Sekwj
ifgc9OYLcQM9U9tKJ8PhacBbV/QduIUTBl6YPmeGDdU0/4WMfE1UYORlV2XAtLn/
BScOS5A/1OUE6qiQGJLJn/ZUn7+ApwrkrN09UYUH1x9BhwqphzJ0E3AQY9tjUZ+g
ngHQM9FSLT20Fz0XTz1V3BfBfehGM3l+jNuHWX4Ay9eJ9iWVsQihhgjW512w4AFq
n1knYaQWptjRBNlIxfUSvDYpSxgOW+SBgQKCAQEA7ikfNUZDmhyShcmIl9Hgcral
o2M/ggUVwWd9AaJD+Y/WcGoR0DPGt8UGLGTBNBwbyTgHdDzsWA+02r5r+5ArhhnP
iWQ1soQI9FpZIUCyzAjTQpfpzo5dGqpQbW9LuHJOEbDyY2wG+lFhIm4JJBJ/vws1
yt9Y170VbPXmDdLevDLmlFOILdMJWWl3hrtlU3KEogqWKDOXciYtG5Ji0+512BqH
yY9+uVNb1eu6MLU5R5U9GdvOFZZjShIhOlpZVR1K21dg5frBCWBZ0pvu4fZf2FAV
lX6+ORENSjqJsQWTaeiMoAPOj8QxQuOwUCajbVkrCZV6D49E0D9XxmZcuKCAXg==
-----END RSA PRIVATE KEY-----`;
const SAML_CERT = "MIIFOjCCAyICCQCqP5DN+xQZDjANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHRmxvcmlkYTEQMA4GA1UEBwwHT3JsYW5kbzENMAsGA1UECgwEVGVzdDEdMBsGCSqGSIb3DQEJARYOdGVzdEBnbWFpbC5jb20wHhcNMjMxMTE5MTIzNzE3WhcNMzMxMTE2MTIzNzE3WjBfMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHRmxvcmlkYTEQMA4GA1UEBwwHT3JsYW5kbzENMAsGA1UECgwEVGVzdDEdMBsGCSqGSIb3DQEJARYOdGVzdEBnbWFpbC5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD5giLoLyED41IHt0RxB/k6x4K0vzAKiGecPyedRNR1oyiv3OYkuG5jgTE2wcPZc7kD1Eg5d6th0BWHy/ovaNS5mkgnOV6jKkMaWW4sCMSnLnaWy0seftPK3O4mNeZpM5e9amj2gXnZvKrK8cqnJ/bsUUQvXxttXNVVmOHWg/t3c2vJ4XuUfph6wIKbrj297ILzuAFRNvAVxeS0tElwepvZ5Wbf7Hc1MORAqTpw/mp8cRjHRzYCA9y6OM4hgVs1gvTJS8WGoMmsdAZHaOnv9vLJvW3jDLQQecOheYIJncWgcESzJFIkmXadorYCEfWhwwBdVphknmeLr4BMpJBclAYaFjYDLIKpMcXYO5k/2r3BgSPlw4oqbxbR5geD05myKYtZ/wNUtku118NjhIfJFulU/kfDcp1rYYkvzgBfqr80wgNps4oQzVr1mnpgHsSTAhXMuZbaTByJRmPqecyvyQqRQcRIN0oTLJNGyzoUf0RkH6DKJ4+7qDhlq4Zhlfso9OFMv9xeONfIrJo5HtTfFZfidkXZqir2ZqwqNlNOMfK5DsYq37x2Gkgqig4nqLpITXyxfnQpL2HsaoFrlctt/OL+Zqba7NT4heYk9GX8qlAS+Ipsv6T2HSANbah55oSS3uvcrDOug2Zq7+GYMLKS1IKUKhwX+wLMxmMwSJQ9ZgFwfQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCkGPZdflocTSXIe5bbehsBn/IPdyb38eH2HaAvWqO2XNcDcq+6/uLc8BVK4JMa3AFS9xtBza7MOXN/lw/Ccb8uJGVNUE31+rTvsJaDtMCQkp+9aG04I1BonEHfSB0ANcTy/Gp+4hKyFCd6x35uyPO7CWX5Z8I87q9LF6Dte3/v1j7VZgDjAi9yHpBJv9Xje33AK1vF+WmEfDUOi8y2B8htVeoyS3owln3ZUbnmJdCmMp2BMRq63ymINwklEaYaNrp1L201bSqNdKZF2sNwROWyDX+WFYgufrnzPYb6HS8gYb4oEZmaG5cBM7Hs730/3BlbHKhxNTy1Io2TVCYcMQD+ieiVg5e5eGTwaPYGuVvY3NVhO8FaYBG7K2NT2hqutdCMaQpGyHEzbbbTY1afhbeMmWWqivRnVJNDv4kgBc2SE8JO82qHikIW9Om0cghC5xwTT+1JTtxxD1KeC1M1IwLzzuuMmwJSKAsv4duDqN+YRIP78J2SlrssqlsmoF8+48e7Vzr7JRT/Ya274P8RpUPNtxTR7WDmZ4tunqXjiBpz6l0uTtVXnj5UBo4HCyRjWJOGf15OCuQX03qz8tKn1IbZUf723qrmSF+cxBwHqpAywqhTSsaLjIXKnQ0UlMov7QWb0a5N07JZMdMSerbHvbXd/z9S1Ssea2+EGuTYuQur3A==";

function samlIdpMetadata(base) {
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${base}/metadata"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${SAML_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${base}/slo"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${base}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

async function samlLoginResponse({ metadata, id, issuer, acs, email, name, signAssertion }) {
  const saml = require("samlify");
  const idp = saml.IdentityProvider({
    metadata,
    privateKey: SAML_KEY,
    loginResponseTemplate: {
      context: saml.SamlLib.defaultLoginResponseTemplate.context,
      attributes: [
        { name: "email", valueTag: "email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
        { name: "displayName", valueTag: "displayName", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
      ],
    },
  });
  const sp = saml.ServiceProvider({
    entityID: issuer,
    wantAssertionsSigned: signAssertion,
    assertionConsumerService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: acs }],
  });
  const now = new Date();
  const later = new Date(now.getTime() + 5 * 60 * 1000);
  const responseID = "_" + crypto.randomUUID();
  const { context } = await idp.createLoginResponse(sp, { extract: { request: { id } } }, "post", { email }, (template) => ({
    id: responseID,
    context: saml.SamlLib.replaceTagsByValue(template, {
      ID: responseID,
      AssertionID: "_" + crypto.randomUUID(),
      Destination: acs,
      Audience: issuer,
      SubjectRecipient: acs,
      Issuer: idp.entityMeta.getEntityID(),
      IssueInstant: now.toISOString(),
      StatusCode: "urn:oasis:names:tc:SAML:2.0:status:Success",
      ConditionsNotBefore: now.toISOString(),
      ConditionsNotOnOrAfter: later.toISOString(),
      SubjectConfirmationDataNotOnOrAfter: later.toISOString(),
      NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      NameID: email,
      InResponseTo: id,
      AuthnStatement: "",
      attrEmail: email,
      attrDisplayName: name,
    }),
  }));
  return context;
}
