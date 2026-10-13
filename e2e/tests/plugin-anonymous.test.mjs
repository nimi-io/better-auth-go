// Anonymous plugin parity: the official anonymousClient against the Go server and the
// reference TypeScript server (profile "anonymous"); normalised transcripts must be identical.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { anonymousClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers("anonymous"); });
after(async () => { await servers?.stop(); });

const anonOf = (server) => makeClient(server, { plugins: [anonymousClient()] });

// Generated emails embed a random id; replace them with a stable placeholder.
const PLACEHOLDER = /^[A-Za-z0-9]{32}@anonymous\.placeholder\.invalid$/;
function scrub(v) {
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x)]));
  if (typeof v === "string" && PLACEHOLDER.test(v)) return "<anon-email>";
  return v;
}
async function rec(t, name, c, call) {
  const r = await record(t, name, c, call);
  t[t.length - 1] = scrub(t[t.length - 1]);
  return r;
}

test("anonymous sign-in, repeat rejection and deletion", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = anonOf(server);
    await rec(t, "sign-in anonymous", c, () => c.client.signIn.anonymous());
    await rec(t, "session", c, () => c.client.getSession());
    await rec(t, "sign-in anonymous again", c, () => c.client.signIn.anonymous());
    await rec(t, "delete anonymous user", c, () => c.client.deleteAnonymousUser());
    await rec(t, "session after delete", c, () => c.client.getSession());
    await rec(t, "delete unauthenticated", c, () => c.client.deleteAnonymousUser());
  });
  assert.equal(t[0].data.user.email, "<anon-email>");
  assert.equal(t[1].data.user.isAnonymous, true);
  assert.equal(t[2].error.code, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY");
  assert.equal(t[4].data, null);
});

test("linking an anonymous user on sign-up and sign-in", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = anonOf(server);
    await rec(t, "sign-in anonymous", c, () => c.client.signIn.anonymous());
    await rec(t, "sign-up links", c, () => c.client.signUp.email({ email: "linked@example.com", password: "password1234", name: "Linked" }));
    await rec(t, "session is the new user", c, () => c.client.getSession());
    await rec(t, "delete non-anonymous", c, () => c.client.deleteAnonymousUser());
    const d = anonOf(server);
    await rec(t, "second anonymous", d, () => d.client.signIn.anonymous());
    await rec(t, "sign-in links", d, () => d.client.signIn.email({ email: "linked@example.com", password: "password1234" }));
    await rec(t, "session after sign-in", d, () => d.client.getSession());
    await rec(t, "anonymous again after linking", d, () => d.client.signIn.anonymous());
  });
  assert.equal(t[2].data.user.email, "linked@example.com");
  assert.equal(t[2].data.user.isAnonymous, false);
  assert.equal(t[3].error.code, "USER_IS_NOT_ANONYMOUS");
});
