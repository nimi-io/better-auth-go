// captcha plugin parity (Cloudflare Turnstile); both servers answer siteverify in-process.
import { test, before, after } from "node:test";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers("captcha", { envFor: { go: { MIGRATE: "1" } } }); });
after(async () => { await servers?.stop(); });

const lastVerify = async (server) => (await fetch(`${server.base}/__test/captcha`)).json();
const withToken = (token) => ({ headers: { "x-captcha-response": token } });

test("captcha: protected endpoints, tokens, hostname binding", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up without token", c, () => c.client.signUp.email({ email: "cap@example.com", password: "password1234", name: "C" }));
    await record(t, "sign-up bad token", c, () => c.client.signUp.email({ email: "cap@example.com", password: "password1234", name: "C", fetchOptions: withToken("bad-token") }));
    t.push({ name: "siteverify request", req: await lastVerify(server) });
    await record(t, "sign-up wrong host", c, () => c.client.signUp.email({ email: "cap@example.com", password: "password1234", name: "C", fetchOptions: withToken("wrong-host") }));
    await record(t, "sign-up valid token", c, () => c.client.signUp.email({ email: "cap@example.com", password: "password1234", name: "C", fetchOptions: withToken("valid-token") }));
    await record(t, "get-session unprotected", c, () => c.client.getSession());
    await record(t, "sign-in valid token", c, () => c.client.signIn.email({ email: "cap@example.com", password: "password1234", fetchOptions: withToken("valid-token") }));
    await record(t, "reset request without token", c, () => c.client.requestPasswordReset({ email: "cap@example.com" }));
    await recordFetch(t, "duplicate slashes still protected", c, "/sign-in//email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "cap@example.com", password: "password1234" }) });
    await recordFetch(t, "trailing slash still protected", c, "/sign-in/email/", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "cap@example.com", password: "password1234" }) });
  }, { imageNullEqualsAbsent: true });
});
