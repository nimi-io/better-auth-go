// one-time-token plugin parity through the official oneTimeTokenClient: generate/verify,
// single use, set-ott header on new sessions; plus cross-implementation redemption through a
// shared SQLite database (plain and hashed storage).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { oneTimeTokenClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

const plugins = [oneTimeTokenClient()];
let servers;
before(async () => { servers = await startServers("one-time-token"); });
after(async () => { await servers?.stop(); });

test("one-time-token: generate, verify, single use, set-ott header", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "ott@example.com", password: "password1234", name: "OTT" }));
    const signUpRes = c.state.last;
    t.push({ name: "set-ott on sign-up", ott: /^[A-Za-z0-9_-]{32}$/.test(signUpRes.headers.get("set-ott") ?? ""), expose: signUpRes.headers.get("access-control-expose-headers") });
    const gen = await record(t, "generate", c, () => c.client.oneTimeToken.generate());
    const token = gen.data.token;
    t[t.length - 1].data.token = "<ott>"; // contains "-"/"_", so the harness does not normalise it
    t.push({ name: "token shape", ok: /^[A-Za-z0-9_-]{32}$/.test(token) });
    const other = makeClient(server, { plugins });
    await record(t, "verify", other, () => other.client.oneTimeToken.verify({ token }));
    await record(t, "session from ott", other, () => other.client.getSession());
    await record(t, "verify replay", other, () => other.client.oneTimeToken.verify({ token }));
    await record(t, "verify garbage", other, () => other.client.oneTimeToken.verify({ token: "garbage" }));
    await record(t, "verify missing token", other, () => other.client.oneTimeToken.verify({}));
    const anon = makeClient(server, { plugins });
    await record(t, "generate unauthenticated", anon, () => anon.client.oneTimeToken.generate());
    // set-ott on sign-in too; the header token is itself redeemable
    const res = await recordFetch(t, "sign-in", anon, "/sign-in/email", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "ott@example.com", password: "password1234" }),
    });
    const ott = res.res.headers.get("set-ott");
    t.push({ name: "set-ott on sign-in", ok: !!ott });
    const third = makeClient(server, { plugins });
    await record(t, "verify set-ott token", third, () => third.client.oneTimeToken.verify({ token: ott }));
  });
  assert.equal(t.find((e) => e.name === "verify").status, 200);
  assert.equal(t.find((e) => e.name === "verify replay").error.message, "Invalid token");
});

for (const store of ["plain", "hashed"]) {
  test(`one-time-token: ${store} tokens are interchangeable through a shared database`, async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-ott-"));
    const shared = await startServers("one-time-token", { env: { DB_URL: `sqlite:${path.join(dir, "ott.db")}`, TOKEN_STORE: store } });
    try {
      for (const [from, to] of [["ts", "go"], ["go", "ts"]]) {
        const email = `ott-${store}-${from}@example.com`;
        const gen = makeClient(shared[from], { plugins });
        assert.equal((await gen.client.signUp.email({ email, password: "password1234", name: "S" })).error, null);
        const { data } = await gen.client.oneTimeToken.generate();
        const v = makeClient(shared[to], { plugins });
        const ok = await v.client.oneTimeToken.verify({ token: data.token });
        assert.equal(ok.error, null, `${store} ${from}->${to}: ${JSON.stringify(ok.error)}`);
        assert.equal(ok.data.user.email, email);
      }
    } finally {
      await shared.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
