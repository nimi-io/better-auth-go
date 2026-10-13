// one-tap parity: Google One Tap id tokens signed by the mock IdP (Google JWKS host rewritten
// to servers/mock-idp.mjs) on both servers.
import { test, before, after } from "node:test";
import { oneTapClient } from "better-auth/client/plugins";
import { startServers, startIdp, makeClient, dual, record } from "../lib/harness.mjs";

let idp;
const running = [];
before(async () => { idp = await startIdp(); });
after(async () => {
  for (const s of running) await s.stop();
  idp?.stop();
});

async function idToken(claims) {
  const r = await fetch(`${idp.base}/__idp/id-token?claims=${encodeURIComponent(JSON.stringify(claims))}`);
  return (await r.json()).token;
}

const oneTap = (c, body) => c.client.$fetch("/one-tap/callback", { method: "POST", body });

test("one-tap: sign-in, repeat sign-in, invalid tokens", async () => {
  const servers = await startServers("one-tap", { env: { IDP_URL: idp.base } });
  running.push(servers);
  await dual(servers, async (server, t) => {
    const plugins = [oneTapClient({ clientId: "google-client" })];
    const c = makeClient(server, { plugins });
    const base = { iss: "https://accounts.google.com", aud: "google-client", email_verified: true };
    const tok = await idToken({ ...base, sub: "ot-1", email: "OneTap@Example.com", name: "One Tap", picture: "https://p/ot.png" });
    await record(t, "one-tap sign-in", c, () => oneTap(c, { idToken: tok }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "accounts", c, () => c.client.listAccounts());
    const c2 = makeClient(server, { plugins });
    await record(t, "repeat sign-in", c2, () => oneTap(c2, { idToken: tok, callbackURL: "/dashboard" }));
    await record(t, "untrusted callbackURL", c2, () => oneTap(c2, { idToken: tok, callbackURL: "https://evil.example.com/x" }));
    await record(t, "wrong audience", c2, async () => oneTap(c2, { idToken: await idToken({ ...base, aud: "other", sub: "ot-2", email: "x@example.com" }) }));
    await record(t, "wrong issuer", c2, async () => oneTap(c2, { idToken: await idToken({ ...base, iss: "https://evil", sub: "ot-3", email: "y@example.com" }) }));
    await record(t, "no email", c2, async () => oneTap(c2, { idToken: await idToken({ ...base, sub: "ot-4" }) }));
    await record(t, "not a jwt", c2, () => oneTap(c2, { idToken: "garbage" }));
    await record(t, "missing idToken", c2, () => oneTap(c2, {}));
    // implicit linking: local unverified user is not linked
    const c3 = makeClient(server, { plugins });
    await record(t, "sign-up local", c3, () => c3.client.signUp.email({ email: "local@example.com", password: "password1234", name: "Local" }));
    await record(t, "unverified local link refused", c3, async () => oneTap(c3, { idToken: await idToken({ ...base, sub: "ot-5", email: "local@example.com" }) }));
  });
});

test("one-tap: plugin clientId and disableSignup", async () => {
  const servers = await startServers("one-tap-client-id", { env: { IDP_URL: idp.base } });
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const base = { iss: "accounts.google.com", aud: "one-tap-client", email_verified: true };
    await record(t, "sign-up disabled", c, async () => oneTap(c, { idToken: await idToken({ ...base, sub: "otc-1", email: "new@example.com" }) }));
    await record(t, "sign-up local", c, () => c.client.signUp.email({ email: "known@example.com", password: "password1234", name: "Known" }));
  });
});
