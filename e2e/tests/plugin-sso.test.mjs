// sso parity: @better-auth/sso on both servers. OIDC providers discover the mock IdP's generic
// issuer (servers/mock-idp.mjs /oidc); SAML providers use the mock IdP's SAML endpoints (/saml),
// whose responses are signed by samlify. Transcripts are diffed, and a shared sqlite database
// checks that providers registered on one implementation work on the other.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ssoClient } from "@better-auth/sso/client";
import { startServers, startIdp, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let idp;
let servers;
before(async () => {
  idp = await startIdp();
  servers = await startServers("sso", { env: { IDP_URL: idp.base } });
});
after(async () => {
  await servers?.stop();
  idp?.stop();
});

const code = (profile) => "code-" + Buffer.from(JSON.stringify(profile)).toString("base64url");
const client = (server) => makeClient(server, { plugins: [ssoClient()] });

function mask(value, server) {
  if (typeof value === "string") return value.split(idp.base).join("<idp>").split(encodeURIComponent(idp.base)).join("<idp>").split(encodeURIComponent(server.base)).join("<base>");
  if (Array.isArray(value)) return value.map((v) => mask(v, server));
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value)) out[k] = mask(value[k], server);
    return out;
  }
  return value;
}

function maskURL(raw, server) {
  const u = new URL(raw);
  const params = {};
  for (const [k, v] of u.searchParams) {
    params[k] = ["state", "SAMLRequest", "RelayState", "code_challenge"].includes(k) ? `<${k}>` : mask(v, server).split(server.base).join("<base>");
  }
  return { endpoint: mask(`${u.origin}${u.pathname}`, server), params, order: [...u.searchParams.keys()].join(",") };
}

function last(t) {
  return t[t.length - 1];
}

async function signUp(t, c, email) {
  await record(t, "sign-up", c, () => c.client.signUp.email({ email, password: "password1234", name: "SSO Admin" }));
}

async function registerOIDC(t, c, providerId, domain) {
  await record(t, `register ${providerId}`, c, () => c.client.sso.register({
    providerId,
    issuer: `${idp.base}/oidc`,
    domain,
    oidcConfig: { clientId: "oidc-client", clientSecret: "oidc-secret", mapping: { email: "email", name: "name", emailVerified: "email_verified" } },
  }));
  last(t).data = mask(last(t).data, c.server);
}

async function startOIDC(t, c, name, body) {
  const r = await record(t, name, c, () => c.client.signIn.sso(body));
  const url = r.data?.url;
  if (url) last(t).data = { ...last(t).data, url: maskURL(url, c.server) };
  return url ? new URL(url) : null;
}

async function oidcCallback(t, c, name, providerId, u, profile) {
  await recordFetch(t, name, c, `/sso/callback/${providerId}?code=${code(profile)}&state=${encodeURIComponent(u.searchParams.get("state"))}`);
}

async function samlMetadata() {
  return (await fetch(`${idp.base}/saml/metadata`)).text();
}

async function registerSAML(t, c, providerId, domain, extra = {}) {
  const metadata = await samlMetadata();
  await record(t, `register ${providerId}`, c, () => c.client.sso.register({
    providerId,
    issuer: `${c.server.base}/sp/${providerId}`,
    domain,
    samlConfig: {
      entryPoint: `${idp.base}/saml/sso`,
      callbackUrl: "/dashboard",
      idpMetadata: { metadata },
      mapping: { email: "email", name: "displayName" },
      ...extra,
    },
  }));
  last(t).data = mask(last(t).data, c.server);
}

/** Runs the SP-initiated SAML flow: sign-in, IdP response, ACS POST. */
async function samlSignIn(t, c, providerId, email, { signAssertion = false, callbackURL = "/dashboard" } = {}) {
  const r = await record(t, `saml sign-in ${email}`, c, () => c.client.signIn.sso({ providerId, callbackURL }));
  const url = r.data?.url;
  if (url) last(t).data = { ...last(t).data, url: maskURL(url, c.server) };
  if (!url) return null;
  const sso = new URL(url);
  sso.searchParams.set("email", email);
  if (signAssertion) sso.searchParams.set("signAssertion", "1");
  const idpRes = await (await fetch(sso)).json();
  return recordFetch(t, `acs ${email}`, c, `/sso/saml2/sp/acs/${providerId}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ SAMLResponse: idpRes.SAMLResponse, RelayState: idpRes.RelayState ?? "" }).toString(),
  });
}

test("sso: OIDC provider registration, sign-in and provider management", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = client(server);
    await signUp(t, c, "oidc-admin@example.com");
    await registerOIDC(t, c, "acme-oidc", "acme.example");
    await record(t, "duplicate providerId", c, () => c.client.sso.register({
      providerId: "acme-oidc", issuer: `${idp.base}/oidc`, domain: "acme.example", oidcConfig: { clientId: "x", clientSecret: "y" },
    }));
    await record(t, "reserved providerId", c, () => c.client.sso.register({
      providerId: "credential", issuer: `${idp.base}/oidc`, domain: "acme.example", oidcConfig: { clientId: "x", clientSecret: "y" },
    }));
    await record(t, "invalid issuer", c, () => c.client.sso.register({ providerId: "bad", issuer: "not-a-url", domain: "bad.example" }));
    await record(t, "list providers", c, () => c.client.sso.providers());
    last(t).data = mask(last(t).data, server);
    await record(t, "get provider", c, () => c.client.sso.getProvider({ query: { providerId: "acme-oidc" } }));
    last(t).data = mask(last(t).data, server);

    // sign-in by email domain, PKCE + discovery
    const u = await startOIDC(t, c, "sign-in by email", { email: "alice@acme.example", callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
    // the state cookie belongs to the initiating browser: another browser is rejected
    const other = client(server);
    await oidcCallback(t, other, "callback from another browser", "acme-oidc", u, { sub: "alice-1", email: "alice@acme.example", name: "Alice", email_verified: true });
    const c2 = client(server);
    const u2 = await startOIDC(t, c2, "sign-in by providerId", { providerId: "acme-oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome", loginHint: "bob" });
    await oidcCallback(t, c2, "callback new user", "acme-oidc", u2, { sub: "bob-1", email: "bob@acme.example", name: "Bob", email_verified: true });
    await record(t, "session", c2, () => c2.client.getSession());
    await record(t, "accounts", c2, () => c2.client.listAccounts());
    const c3 = client(server);
    const u3 = await startOIDC(t, c3, "sign-in by domain", { domain: "acme.example", callbackURL: "/dashboard", errorCallbackURL: "/oops" });
    await oidcCallback(t, c3, "callback existing user", "acme-oidc", u3, { sub: "bob-1", email: "bob@acme.example", name: "Bob", email_verified: true });
    await record(t, "session again", c3, () => c3.client.getSession());
    const c4 = client(server);
    const u4 = await startOIDC(t, c4, "sign-in for error", { providerId: "acme-oidc", callbackURL: "/dashboard", errorCallbackURL: "/oops" });
    await recordFetch(t, "callback provider error", c4, `/sso/callback/acme-oidc?error=access_denied&error_description=denied&state=${encodeURIComponent(u4.searchParams.get("state"))}`);
    await recordFetch(t, "callback missing state", c4, "/sso/callback/acme-oidc?code=abc");
    await record(t, "unknown provider", c4, () => c4.client.signIn.sso({ providerId: "nope", callbackURL: "/dashboard" }));
    await record(t, "missing identifier", c4, () => c4.client.signIn.sso({ callbackURL: "/dashboard" }));

    await record(t, "update provider", c, () => c.client.sso.updateProvider({ providerId: "acme-oidc", domain: "acme2.example" }));
    last(t).data = mask(last(t).data, server);
    await record(t, "update nothing", c, () => c.client.sso.updateProvider({ providerId: "acme-oidc" }));
    await record(t, "delete other user's provider", c2, () => c2.client.sso.deleteProvider({ providerId: "acme-oidc" }));
    await record(t, "delete provider", c, () => c.client.sso.deleteProvider({ providerId: "acme-oidc" }));
    await record(t, "list after delete", c, () => c.client.sso.providers());
  });
  assert.equal(t.find((e) => e.name === "session").data.user.email, "bob@acme.example");
  assert.equal(t.find((e) => e.name === "callback new user").location, "/welcome");
});

test("sso: SAML SP-initiated and IdP-initiated sign-in, metadata and single logout", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = client(server);
    await signUp(t, c, "saml-admin@example.com");
    await registerSAML(t, c, "acme-saml", "saml.example");
    const meta = await recordFetch(t, "sp metadata", c, "/sso/saml2/sp/metadata?providerId=acme-saml");
    last(t).data = mask(last(t).data, server);
    assert.match(String(meta.data), /AssertionConsumerService/);

    const user = client(server);
    await samlSignIn(t, user, "acme-saml", "carol@saml.example");
    await record(t, "saml session", user, () => user.client.getSession());
    await record(t, "saml accounts", user, () => user.client.listAccounts());

    // replaying the same response is rejected
    const replay = client(server);
    const r = await record(t, "replay sign-in", replay, () => replay.client.signIn.sso({ providerId: "acme-saml", callbackURL: "/dashboard" }));
    last(t).data = { ...last(t).data, url: maskURL(r.data.url, server) };
    const sso = new URL(r.data.url);
    sso.searchParams.set("email", "dave@saml.example");
    const idpRes = await (await fetch(sso)).json();
    const form = { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ SAMLResponse: idpRes.SAMLResponse, RelayState: idpRes.RelayState }).toString() };
    await recordFetch(t, "acs first", replay, "/sso/saml2/sp/acs/acme-saml", form);
    await recordFetch(t, "acs replay", replay, "/sso/saml2/sp/acs/acme-saml", form);

    // tampered response
    const bad = client(server);
    const r2 = await bad.client.signIn.sso({ providerId: "acme-saml", callbackURL: "/dashboard" });
    const sso2 = new URL(r2.data.url);
    sso2.searchParams.set("email", "eve@saml.example");
    const res2 = await (await fetch(sso2)).json();
    const tampered = Buffer.from(Buffer.from(res2.SAMLResponse, "base64").toString().replace("eve@saml.example", "admin@saml.example")).toString("base64");
    await recordFetch(t, "acs tampered", bad, "/sso/saml2/sp/acs/acme-saml", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ SAMLResponse: tampered, RelayState: res2.RelayState }).toString() });
    await recordFetch(t, "acs garbage", bad, "/sso/saml2/sp/acs/acme-saml", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "SAMLResponse=bm90IHhtbA%3D%3D" });

    // IdP-initiated (allowIdpInitiated)
    const unsolicited = client(server);
    const acs = `${server.base}/api/auth/sso/saml2/sp/acs/acme-saml`;
    const res3 = await (await fetch(`${idp.base}/saml/idp-initiated?acs=${encodeURIComponent(acs)}&audience=${encodeURIComponent(`${server.base}/sp/acme-saml`)}&email=frank@saml.example`)).json();
    await recordFetch(t, "idp-initiated acs", unsolicited, "/sso/saml2/sp/acs/acme-saml", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ SAMLResponse: res3.SAMLResponse }).toString() });
    await record(t, "idp-initiated session", unsolicited, () => unsolicited.client.getSession());

    // SP-initiated single logout
    const slo = await recordFetch(t, "initiate slo", user, "/sso/saml2/logout/acme-saml", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ callbackURL: "/bye" }) });
    if (slo.res.headers.get("location")) last(t).location = maskURL(slo.res.headers.get("location"), server);
    await record(t, "session after slo", user, () => user.client.getSession());
    await recordFetch(t, "slo without data", user, "/sso/saml2/sp/slo/acme-saml");

    // registration validation
    await record(t, "saml missing idp authority", c, () => c.client.sso.register({
      providerId: "broken", issuer: `${server.base}/sp/broken`, domain: "broken.example",
      samlConfig: { entryPoint: `${idp.base}/saml/sso`, idpMetadata: {} },
    }));
    await record(t, "saml missing cert", c, () => c.client.sso.register({
      providerId: "broken", issuer: `${server.base}/sp/broken`, domain: "broken.example",
      samlConfig: { entryPoint: `${idp.base}/saml/sso`, idpMetadata: { entityID: `${idp.base}/saml/metadata` } },
    }));
  });
  assert.equal(t.find((e) => e.name === "saml session").data.user.email, "carol@saml.example");
  assert.equal(t.find((e) => e.name === "acs carol@saml.example").location, "/dashboard");
  assert.match(t.find((e) => e.name === "acs replay").location, /Unknown%20or%20expired%20request%20ID/);
});

test("sso: providers registered on one server work on the other (shared database)", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-sso-"));
  const url = `sqlite:${path.join(dir, "shared.db")}`;
  const shared = await startServers("sso", { env: { DB_URL: url, IDP_URL: idp.base }, envFor: { ts: { MIGRATE: "1" } } });
  try {
    // OIDC provider registered on Go, used on TypeScript
    const goAdmin = client(shared.go);
    assert.equal((await goAdmin.client.signUp.email({ email: "shared-admin@example.com", password: "password1234", name: "Admin" })).error, null);
    const reg = await goAdmin.client.sso.register({
      providerId: "shared-oidc", issuer: `${idp.base}/oidc`, domain: "shared.example",
      oidcConfig: { clientId: "oidc-client", clientSecret: "oidc-secret" },
    });
    assert.equal(reg.error, null, JSON.stringify(reg.error));
    const tsUser = client(shared.ts);
    const s = await tsUser.client.signIn.sso({ email: "zoe@shared.example", callbackURL: "/dashboard" });
    assert.equal(s.error, null, JSON.stringify(s.error));
    const u = new URL(s.data.url);
    const cb = await tsUser.fetch(`${shared.ts.base}/api/auth/sso/callback/shared-oidc?code=${code({ sub: "zoe", email: "zoe@shared.example", email_verified: true })}&state=${encodeURIComponent(u.searchParams.get("state"))}`);
    assert.equal(cb.status, 302);
    assert.equal(cb.headers.get("location"), "/dashboard");
    assert.equal((await tsUser.client.getSession()).data?.user.email, "zoe@shared.example");
    // the TypeScript server sees the Go-registered provider through its management API
    const tsAdmin = client(shared.ts);
    await tsAdmin.client.signIn.email({ email: "shared-admin@example.com", password: "password1234" });
    const got = await tsAdmin.client.sso.getProvider({ query: { providerId: "shared-oidc" } });
    assert.equal(got.error, null, JSON.stringify(got.error));
    assert.equal(got.data.type, "oidc");

    // SAML provider registered on TypeScript, used on Go
    const metadata = await samlMetadata();
    const reg2 = await tsAdmin.client.sso.register({
      providerId: "shared-saml", issuer: "https://sp.shared.example/saml", domain: "saml-shared.example",
      samlConfig: { entryPoint: `${idp.base}/saml/sso`, callbackUrl: "/dashboard", idpMetadata: { metadata }, mapping: { email: "email", name: "displayName" } },
    });
    assert.equal(reg2.error, null, JSON.stringify(reg2.error));
    const goUser = client(shared.go);
    const s2 = await goUser.client.signIn.sso({ providerId: "shared-saml", callbackURL: "/dashboard" });
    assert.equal(s2.error, null, JSON.stringify(s2.error));
    const sso = new URL(s2.data.url);
    sso.searchParams.set("email", "yuki@saml-shared.example");
    sso.searchParams.set("signAssertion", "1");
    const idpRes = await (await fetch(sso)).json();
    const acs = await goUser.fetch(`${shared.go.base}/api/auth/sso/saml2/sp/acs/shared-saml`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ SAMLResponse: idpRes.SAMLResponse, RelayState: idpRes.RelayState }).toString(),
    });
    assert.equal(acs.status, 302);
    assert.equal(acs.headers.get("location"), "/dashboard");
    assert.equal((await goUser.client.getSession()).data?.user.email, "yuki@saml-shared.example");
    // Go lists the TypeScript-registered provider with the same sanitized shape
    const goView = await goAdmin.client.sso.getProvider({ query: { providerId: "shared-saml" } });
    const tsView = await tsAdmin.client.sso.getProvider({ query: { providerId: "shared-saml" } });
    const strip = (v, base) => JSON.parse(JSON.stringify(v).split(base).join("<base>"));
    assert.deepEqual(strip(goView.data, shared.go.base), strip(tsView.data, shared.ts.base));
  } finally {
    await shared.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
