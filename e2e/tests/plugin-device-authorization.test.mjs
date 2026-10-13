// Device authorization (RFC 8628) parity: the official deviceAuthorizationClient against the
// Go server and the reference TypeScript server (profile "device-authorization");
// normalised transcripts must be identical.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers("device-authorization"); });
after(async () => { await servers?.stop(); });

const clientOf = (server, opts) => makeClient(server, { plugins: [deviceAuthorizationClient()], ...opts });
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Replaces generated codes and tokens with placeholders.
function scrubber() {
  const values = new Map();
  const add = (v, name) => { if (typeof v === "string" && v) values.set(v, name); };
  const scrub = (v) => {
    if (Array.isArray(v)) return v.map(scrub);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x)]));
    if (typeof v === "string") {
      let s = v;
      for (const [val, name] of values) s = s.split(val).join(name);
      return s;
    }
    return v;
  };
  return { add, scrub };
}

async function rec(t, sc, name, c, call) {
  const r = await record(t, name, c, call);
  t[t.length - 1] = sc.scrub(t[t.length - 1]);
  return r;
}

test("device authorization flow: code, polling, verification, approval and token", async () => {
  const t = await dual(servers, async (server, t) => {
    const sc = scrubber();
    sc.add(server.base, "<base>");
    const device = clientOf(server, { origin: null });
    const user = clientOf(server);
    const other = clientOf(server);
    await rec(t, sc, "code invalid client", device, () => device.client.device.code({ client_id: "bad-client" }));
    await rec(t, sc, "code missing client", device, () => device.client.device.code({}));
    const code = await device.client.device.code({ client_id: "tv-app", scope: "read write" });
    sc.add(code.data.device_code, "<device_code>");
    sc.add(code.data.user_code, "<user_code>");
    sc.add(code.data.user_code.toLowerCase(), "<user_code_lower>");
    t.push(sc.scrub({ name: "code", status: device.state.last.status, data: code.data,
      cacheControl: device.state.last.headers.get("cache-control"), pragma: device.state.last.headers.get("pragma") }));
    const { device_code, user_code } = code.data;
    await rec(t, sc, "token pending", device, () => device.client.device.token({ grant_type: GRANT, device_code, client_id: "tv-app" }));
    await rec(t, sc, "token slow down", device, () => device.client.device.token({ grant_type: GRANT, device_code, client_id: "tv-app" }));
    await rec(t, sc, "token client mismatch", device, () => device.client.device.token({ grant_type: GRANT, device_code, client_id: "other-app" }));
    await rec(t, sc, "token bad grant type", device, () => device.client.device.token({ grant_type: "password", device_code, client_id: "tv-app" }));
    await rec(t, sc, "verify anonymous", other, () => other.client.device({ query: { user_code } }));
    await rec(t, sc, "verify invalid code", other, () => other.client.device({ query: { user_code: "NOPE" } }));
    await rec(t, sc, "approve unauthenticated", other, () => other.client.device.approve({ userCode: user_code }));
    await rec(t, sc, "sign up", user, () => user.client.signUp.email({ email: "device@example.com", password: "password1234", name: "Device User" }));
    await rec(t, sc, "verify lowercase with session", user, () => user.client.device({ query: { user_code: user_code.toLowerCase() } }));
    await rec(t, sc, "verify with session", user, () => user.client.device({ query: { user_code } }));
    await rec(t, sc, "sign up other", other, () => other.client.signUp.email({ email: "other@example.com", password: "password1234", name: "Other" }));
    await rec(t, sc, "verify by other user", other, () => other.client.device({ query: { user_code } }));
    await rec(t, sc, "approve by other user", other, () => other.client.device.approve({ userCode: user_code }));
    await rec(t, sc, "approve", user, () => user.client.device.approve({ userCode: user_code }));
    await rec(t, sc, "approve again", user, () => user.client.device.approve({ userCode: user_code }));
    await sleep(2100);
    const tok = await device.client.device.token({ grant_type: GRANT, device_code, client_id: "tv-app" });
    sc.add(tok.data?.access_token, "<access_token>");
    t.push(sc.scrub({ name: "token", status: device.state.last.status, data: { ...tok.data, expires_in: tok.data?.expires_in > 0 },
      error: tok.error ?? null, cacheControl: device.state.last.headers.get("cache-control") }));
    await rec(t, sc, "token reuse", device, () => device.client.device.token({ grant_type: GRANT, device_code, client_id: "tv-app" }));
    const s = await fetch(`${server.base}/__test/session`, { headers: { authorization: `Bearer ${tok.data.access_token}`, cookie: `better-auth.session_token=${tok.data.access_token}` } });
    t.push({ name: "token is a session token", ok: s.ok });

    // deny flow
    const code2 = await device.client.device.code({ client_id: "tv-app" });
    sc.add(code2.data.device_code, "<device_code2>");
    sc.add(code2.data.user_code, "<user_code2>");
    await rec(t, sc, "verify second", user, () => user.client.device({ query: { user_code: code2.data.user_code } }));
    await rec(t, sc, "deny", user, () => user.client.device.deny({ userCode: code2.data.user_code }));
    await rec(t, sc, "token denied", device, () => device.client.device.token({ grant_type: GRANT, device_code: code2.data.device_code, client_id: "tv-app" }));
    await rec(t, sc, "token after denial", device, () => device.client.device.token({ grant_type: GRANT, device_code: code2.data.device_code, client_id: "tv-app" }));

    // form-encoded requests (RFC 8628 section 3.1)
    const form = (body) => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    const f1 = await recordFetch(t, "form code", device, "/device/code", form("client_id=tv-app&scope=&user_id="));
    sc.add(f1.data.device_code, "<device_code3>");
    sc.add(f1.data.user_code, "<user_code3>");
    t[t.length - 1] = sc.scrub(t[t.length - 1]);
    await recordFetch(t, "form repeated client_id", device, "/device/code", form("client_id=tv-app&client_id=tv-app2"));
    await recordFetch(t, "form empty client_id", device, "/device/code", form("client_id="));
  });
  assert.equal(t[2].data.verification_uri, "<base>/device?lang=en");
  assert.equal(t[2].data.verification_uri_complete, "<base>/device?lang=en&user_code=<user_code>");
  assert.equal(t[3].error.status, 400);
  const byName = Object.fromEntries(t.map((e) => [e.name, e]));
  assert.equal(byName["token"].data.token_type, "Bearer");
  assert.equal(byName["token"].data.scope, "read write");
  assert.equal(byName["token denied"].data, null);
});
