// Passkey plugin parity (@better-auth/passkey). The official passkeyClient needs a
// browser for navigator.credentials, so the ceremonies are driven through the client's
// $fetch / passkey actions with a node:crypto software authenticator
// (lib/passkey-authenticator.mjs). Transcripts of the Go and TypeScript servers must match.
// The cross-compatibility tests share one SQLite database between both servers: passkeys
// registered on one implementation sign in on the other.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { passkeyClient } from "@better-auth/passkey/client";
import { startServers, makeClient, dual, record, recordFetch, uniqueEmail } from "../lib/harness.mjs";
import { SoftAuthenticator } from "../lib/passkey-authenticator.mjs";

const plugins = [passkeyClient()];
const json = (body) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

// Replaces values that are random per ceremony (challenges, WebAuthn user handles,
// credential ids and public keys) with placeholders.
function scrub(v, ctx = {}) {
  if (Array.isArray(v)) return v.map((x) => scrub(x, ctx));
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === "challenge" && typeof x === "string") out[k] = "<challenge>";
      else if (k === "credentialID" || k === "publicKey") out[k] = x ? `<${k}>` : x;
      else if (k === "user" && x && typeof x === "object" && "displayName" in x) out[k] = { ...x, id: "<user-handle>" };
      else if ((k === "excludeCredentials" || k === "allowCredentials") && Array.isArray(x)) out[k] = x.map((c) => ({ ...c, id: "<credential>" }));
      else out[k] = scrub(x, ctx);
    }
    return out;
  }
  return v;
}

async function rec(t, name, c, call) {
  const r = await record(t, name, c, call);
  t[t.length - 1].data = scrub(t[t.length - 1].data);
  return r;
}

async function recRaw(t, name, c, pathname, init) {
  const r = await recordFetch(t, name, c, pathname, init);
  t[t.length - 1].data = scrub(t[t.length - 1].data);
  return r;
}

describe("passkey plugin", () => {
  let servers;
  before(async () => { servers = await startServers("passkey"); });
  after(async () => { await servers?.stop(); });

  test("registration, sign-in and management ceremonies", async () => {
    const t = await dual(servers, async (server, t) => {
      const c = makeClient(server, { plugins });
      const authr = new SoftAuthenticator({ origin: server.base });
      const packed = new SoftAuthenticator({ origin: server.base, attestation: "packed" });
      await record(t, "sign-up", c, () => c.client.signUp.email({ email: "passkey@example.com", password: "password1234", name: "Passkey User" }));

      const opts = await rec(t, "register options", c, () => c.client.$fetch("/passkey/generate-register-options", { method: "GET" }));
      await rec(t, "verify registration", c, () => c.client.$fetch("/passkey/verify-registration", { method: "POST", body: { response: authr.register(opts.data), name: "  Laptop  " } }));
      await rec(t, "replayed registration", c, () => c.client.$fetch("/passkey/verify-registration", { method: "POST", body: { response: authr.register(opts.data) } }));

      const opts2 = await rec(t, "register options (attachment, name, context)", c, () => c.client.$fetch("/passkey/generate-register-options", { method: "GET", query: { authenticatorAttachment: "cross-platform", name: "custom-name", context: "ctx" } }));
      await rec(t, "verify packed registration", c, () => c.client.$fetch("/passkey/verify-registration", { method: "POST", body: { response: packed.register(opts2.data) } }));
      await rec(t, "register options with existing", c, () => c.client.$fetch("/passkey/generate-register-options", { method: "GET" }));

      const list = await rec(t, "list", c, () => c.client.passkey.listUserPasskeys());
      const laptop = list.data.find((p) => p.name === "Laptop");
      await rec(t, "update", c, () => c.client.passkey.updatePasskey({ id: laptop.id, name: " Work laptop " }));
      await rec(t, "update whitespace", c, () => c.client.passkey.updatePasskey({ id: laptop.id, name: "   " }));
      await rec(t, "update missing", c, () => c.client.passkey.updatePasskey({ id: "does-not-exist", name: "x" }));

      // session sign-in (allowCredentials) and discoverable sign-in (no session)
      const a1 = await rec(t, "authenticate options (session)", c, () => c.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" }));
      await rec(t, "verify authentication", c, () => c.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: authr.authenticate(a1.data) } }));
      await record(t, "sign-out", c, () => c.client.signOut());
      const a2 = await rec(t, "authenticate options (anonymous)", c, () => c.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" }));
      await rec(t, "verify authentication (packed)", c, () => c.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: packed.authenticate(a2.data) } }));
      await rec(t, "session", c, () => c.client.getSession());
      const a3 = await rec(t, "authenticate options again", c, () => c.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" }));
      packed.counter = 0;
      await rec(t, "replayed counter", c, () => c.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: packed.authenticate(a3.data) } }));
      const a4 = await rec(t, "authenticate options unknown", c, () => c.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" }));
      await rec(t, "unknown credential", c, () => c.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: new SoftAuthenticator({ origin: server.base }).authenticate(a4.data) } }));
      const a5 = await rec(t, "authenticate options wrong origin", c, () => c.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" }));
      authr.origin = "http://evil.example.com";
      await rec(t, "wrong origin", c, () => c.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: authr.authenticate(a5.data) } }));
      authr.origin = server.base;

      await rec(t, "delete", c, () => c.client.passkey.deletePasskey({ id: laptop.id }));
      await rec(t, "delete again", c, () => c.client.passkey.deletePasskey({ id: laptop.id }));
      await rec(t, "list after delete", c, () => c.client.passkey.listUserPasskeys());
    });
    assert.equal(t.find((e) => e.name === "verify registration").status, 200);
    assert.equal(t.find((e) => e.name === "verify registration").data.name, "Laptop");
    assert.equal(t.find((e) => e.name === "verify authentication (packed)").status, 200);
    assert.equal(t.find((e) => e.name === "replayed counter").error.code, "AUTHENTICATION_FAILED");
  });

  test("validation, ceremony gating and ownership", async () => {
    await dual(servers, async (server, t) => {
      const c = makeClient(server, { plugins });
      const other = makeClient(server, { plugins });
      const anon = makeClient(server, { plugins });
      const authr = new SoftAuthenticator({ origin: server.base });
      await record(t, "sign-up", c, () => c.client.signUp.email({ email: "owner@example.com", password: "password1234", name: "Owner" }));
      await record(t, "sign-up other", other, () => other.client.signUp.email({ email: "other@example.com", password: "password1234", name: "Other" }));

      await recRaw(t, "register options unauthenticated", anon, "/passkey/generate-register-options", {});
      await recRaw(t, "list unauthenticated", anon, "/passkey/list-user-passkeys", {});
      await recRaw(t, "bad attachment", c, "/passkey/generate-register-options?authenticatorAttachment=usb", {});
      await recRaw(t, "verify registration without challenge", c, "/passkey/verify-registration", json({ response: {} }));
      const opts = await recRaw(t, "register options", c, "/passkey/generate-register-options", {});
      await recRaw(t, "verify registration missing response", c, "/passkey/verify-registration", json({}));
      await recRaw(t, "verify registration bad name", c, "/passkey/verify-registration", json({ response: {}, name: 5 }));
      await recRaw(t, "verify registration garbage", c, "/passkey/verify-registration", json({ response: { id: "x" } }));
      const opts2 = await recRaw(t, "register options 2", c, "/passkey/generate-register-options", {});
      const reg = authr.register(opts2.data);
      await recRaw(t, "registration by another user", other, "/passkey/verify-registration", json({ response: reg }));
      await recRaw(t, "registration (stale challenge cookie owner)", c, "/passkey/verify-registration", json({ response: reg, createSession: true }));
      void opts;

      // an authentication challenge cannot verify a registration and vice versa
      const auth = await recRaw(t, "authenticate options", c, "/passkey/generate-authenticate-options", {});
      await recRaw(t, "registration with authentication challenge", c, "/passkey/verify-registration", json({ response: reg }));
      const opts3 = await recRaw(t, "register options 3", c, "/passkey/generate-register-options", {});
      await recRaw(t, "authentication with registration challenge", c, "/passkey/verify-authentication", json({ response: authr.authenticate(auth.data) }));
      await recRaw(t, "verify registration ok", c, "/passkey/verify-registration", json({ response: authr.register(opts3.data) }));
      await recRaw(t, "verify authentication missing response", c, "/passkey/verify-authentication", json({}));
      await recRaw(t, "verify authentication array response", c, "/passkey/verify-authentication", json({ response: [] }));

      const list = await recRaw(t, "list", c, "/passkey/list-user-passkeys", {});
      const id = list.data[0].id;
      await recRaw(t, "other updates", other, "/passkey/update-passkey", json({ id, name: "hacked" }));
      await recRaw(t, "other deletes", other, "/passkey/delete-passkey", json({ id }));
      await recRaw(t, "delete empty id", c, "/passkey/delete-passkey", json({ id: "" }));
      await recRaw(t, "update missing fields", c, "/passkey/update-passkey", json({}));
      await recRaw(t, "list still has passkey", c, "/passkey/list-user-passkeys", {});
    });
  });
});

describe("passkey cross-compatibility (shared SQLite database)", () => {
  for (const migrator of ["ts", "go"]) {
    describe(`migrated by ${migrator}`, () => {
      let servers;
      let dir;
      before(async () => {
        dir = mkdtempSync(path.join(tmpdir(), "ba-passkey-"));
        const url = `sqlite:${path.join(dir, "shared.db")}`;
        servers = await startServers("passkey", { env: { DB_URL: url }, envFor: { [migrator]: { MIGRATE: "1" } } });
      });
      after(async () => {
        await servers?.stop();
        rmSync(dir, { recursive: true, force: true });
      });

      for (const [from, to] of [["go", "ts"], ["ts", "go"]]) {
        test(`passkey registered on ${from} signs in on ${to}`, async () => {
          const email = uniqueEmail(`pk-${from}`);
          const reg = makeClient(servers[from], { plugins });
          const su = await reg.client.signUp.email({ email, password: "password1234", name: "Cross" });
          assert.equal(su.error, null, JSON.stringify(su.error));
          for (const attestation of ["none", "packed"]) {
            const authr = new SoftAuthenticator({ origin: servers[from].base, attestation });
            const opts = await reg.client.$fetch("/passkey/generate-register-options", { method: "GET" });
            assert.equal(opts.error, null, JSON.stringify(opts.error));
            const v = await reg.client.$fetch("/passkey/verify-registration", { method: "POST", body: { response: authr.register(opts.data), name: attestation } });
            assert.equal(v.error, null, JSON.stringify(v.error));

            const signIn = makeClient(servers[to], { plugins });
            authr.origin = servers[to].base;
            const a = await signIn.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" });
            const r = await signIn.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: authr.authenticate(a.data) } });
            assert.equal(r.error, null, JSON.stringify(r.error));
            assert.equal(r.data.user.email, email);
            assert.equal((await signIn.client.getSession()).data.user.email, email);

            // the counter written by `to` is enforced by `from`
            const back = makeClient(servers[from], { plugins });
            authr.origin = servers[from].base;
            const a2 = await back.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" });
            authr.counter -= 1;
            const bad = await back.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: authr.authenticate(a2.data) } });
            assert.equal(bad.error?.code, "AUTHENTICATION_FAILED");
            const a3 = await back.client.$fetch("/passkey/generate-authenticate-options", { method: "GET" });
            const ok = await back.client.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: authr.authenticate(a3.data) } });
            assert.equal(ok.error, null, JSON.stringify(ok.error));
          }
          // both implementations list identical rows
          const goList = makeClient(servers.go, { plugins });
          const tsList = makeClient(servers.ts, { plugins });
          for (const c of [goList, tsList]) await c.client.signIn.email({ email, password: "password1234" });
          const gl = (await goList.client.passkey.listUserPasskeys()).data;
          const tl = (await tsList.client.passkey.listUserPasskeys()).data;
          assert.equal(gl.length, 2);
          assert.deepEqual(gl, tl);
        });
      }
    });
  }
});
