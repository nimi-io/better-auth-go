// magic-link plugin parity: sign-in/sign-up links, verification redirects and error URLs run
// against the Go and TypeScript servers through the official magicLinkClient; transcripts
// must match. A shared SQLite database checks that stored tokens (plain, hashed) work across
// implementations.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { magicLinkClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch, lastEmail } from "../lib/harness.mjs";

const plugins = [magicLinkClient()];
let servers;
before(async () => { servers = await startServers("magic-link"); });
after(async () => { await servers?.stop(); });

const linkOf = async (server, email) => lastEmail(server, email, "magic-link");
const rel = (server, url) => url.slice(server.base.length + "/api/auth".length);

test("magic-link: sign-up, sign-in, redirects and errors", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const email = "ml-new@example.com";
    await record(t, "send (new user)", c, () => c.client.signIn.magicLink({ email, name: "Magic", callbackURL: "/dashboard", newUserCallbackURL: "/welcome", errorCallbackURL: "/oops" }));
    let mail = await linkOf(server, email);
    t.push({ name: "link", url: mail.url.split(server.base).join("<base>").replace(/token=[^&]+/, "token=<token>"), tokenShape: /^[A-Za-z]{32}$/.test(mail.token) });
    await recordFetch(t, "verify new user -> newUserCallbackURL", c, rel(server, mail.url));
    await record(t, "session", c, () => c.client.getSession());
    await recordFetch(t, "replay -> errorCallbackURL", c, rel(server, mail.url));

    const c2 = makeClient(server, { plugins });
    await record(t, "send (existing)", c2, () => c2.client.signIn.magicLink({ email, callbackURL: "/dashboard" }));
    mail = await linkOf(server, email);
    await recordFetch(t, "verify existing -> callbackURL", c2, rel(server, mail.url));

    const c3 = makeClient(server, { plugins });
    await record(t, "send (no callback)", c3, () => c3.client.signIn.magicLink({ email }));
    mail = await linkOf(server, email);
    await record(t, "verify json (no callbackURL)", c3, () => c3.client.magicLink.verify({ query: { token: mail.token } }));
    await record(t, "session after json verify", c3, () => c3.client.getSession());

    await recordFetch(t, "invalid token default error", c3, "/magic-link/verify?token=nope");
    await recordFetch(t, "invalid token errorCallbackURL with query", c3, `/magic-link/verify?token=nope&errorCallbackURL=${encodeURIComponent("/err?a=1&b=two words")}`);
    await recordFetch(t, "untrusted callbackURL", c3, `/magic-link/verify?token=nope&callbackURL=${encodeURIComponent("http://evil.example.com")}`);
    await recordFetch(t, "missing token", c3, "/magic-link/verify");
    await record(t, "invalid email", c3, () => c3.client.signIn.magicLink({ email: "not-an-email" }));
    await record(t, "untrusted send callback", c3, () => c3.client.signIn.magicLink({ email, callbackURL: "http://evil.example.com" }));

    // existing unverified user (email/password sign-up) is promoted on verify
    const c4 = makeClient(server, { plugins });
    await record(t, "password sign-up", c4, () => c4.client.signUp.email({ email: "ml-unverified@example.com", password: "password1234", name: "Unv" }));
    await record(t, "send unverified", c4, () => c4.client.signIn.magicLink({ email: "ml-unverified@example.com" }));
    mail = await linkOf(server, "ml-unverified@example.com");
    await record(t, "verify promotes", c4, () => c4.client.magicLink.verify({ query: { token: mail.token } }));
    await record(t, "password no longer works", c4, () => c4.client.signIn.email({ email: "ml-unverified@example.com", password: "password1234" }));
  });
  assert.equal(t.find((e) => e.name === "verify new user -> newUserCallbackURL").location, "<base>/welcome");
  assert.equal(t.find((e) => e.name === "replay -> errorCallbackURL").location, "<base>/oops?error=INVALID_TOKEN");
  assert.equal(t.find((e) => e.name === "verify promotes").data.user.emailVerified, true);
});

for (const store of ["plain", "hashed"]) {
  test(`magic-link: ${store} tokens are interchangeable through a shared database`, async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-ml-"));
    const shared = await startServers("magic-link", { env: { DB_URL: `sqlite:${path.join(dir, "ml.db")}`, TOKEN_STORE: store } });
    try {
      for (const [from, to] of [["ts", "go"], ["go", "ts"]]) {
        const email = `ml-${store}-${from}@example.com`;
        const sender = makeClient(shared[from], { plugins });
        const verifier = makeClient(shared[to], { plugins });
        const sent = await sender.client.signIn.magicLink({ email, name: "Shared" });
        assert.equal(sent.error, null, JSON.stringify(sent.error));
        const mail = await lastEmail(shared[from], email, "magic-link");
        const ok = await verifier.client.magicLink.verify({ query: { token: mail.token } });
        assert.equal(ok.error, null, `${store} ${from}->${to}: ${JSON.stringify(ok.error)}`);
        assert.equal(ok.data.user.email, email);
        assert.equal(ok.data.user.name, "Shared");
      }
    } finally {
      await shared.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
