// Database compatibility: the Go server and the reference TypeScript server share one
// database. Users, sessions, accounts and verification rows written by one implementation
// must work on the other, and signed session cookies are interchangeable (same secret).
// Each database runs twice: once migrated by TypeScript, once migrated by Go.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, makeClient, lastEmail, uniqueEmail } from "../lib/harness.mjs";
import { databases } from "../lib/databases.mjs";

const SESSION = "better-auth.session_token";

function shareSession(from, to) {
  to.jar.set(SESSION, from.jar.get(SESSION));
}

async function sessionOf(c) {
  const r = await c.client.getSession();
  return r.data;
}

for (const db of databases()) {
  for (const migrator of db.migrations === false ? ["none"] : ["ts", "go"]) {
    describe(`shared ${db.name} database${migrator === "none" ? "" : ` (migrated by ${migrator})`}`, () => {
      let servers;
      let cleanup;
      before(async (t) => {
        const created = await db.create();
        if (!created) return;
        cleanup = created.drop;
        servers = await startServers("shared", { env: { DB_URL: created.url }, envFor: { [migrator]: { MIGRATE: "1" } } });
      });
      after(async () => {
        await servers?.stop();
        await cleanup?.();
      });

      test("users, credentials and sessions work across implementations", async (t) => {
        if (!servers) return t.skip(`${db.name} unavailable`);
        const email = uniqueEmail("shared");
        const goC = makeClient(servers.go);
        const tsC = makeClient(servers.ts);

        const signUp = await goC.client.signUp.email({ email, password: "password1234", name: "Shared User" });
        assert.equal(signUp.error, null, JSON.stringify(signUp.error));

        // credential account + scrypt hash written by Go, verified by TypeScript
        const signIn = await tsC.client.signIn.email({ email, password: "password1234" });
        assert.equal(signIn.error, null, JSON.stringify(signIn.error));
        assert.equal(signIn.data.user.id, signUp.data.user.id);

        // session row + signed cookie from TypeScript accepted by Go, and vice versa
        const goView = makeClient(servers.go);
        shareSession(tsC, goView);
        assert.equal((await sessionOf(goView))?.user.email, email);
        const tsView = makeClient(servers.ts);
        shareSession(goC, tsView);
        assert.equal((await sessionOf(tsView))?.user.email, email);

        // updates on one side are visible on the other
        assert.equal((await tsC.client.updateUser({ name: "Renamed On TS" })).error, null);
        assert.equal((await sessionOf(goC)).user.name, "Renamed On TS");
        const sessionsGo = await goC.client.listSessions();
        const sessionsTs = await tsC.client.listSessions();
        assert.equal(sessionsGo.data.length, 2);
        assert.deepEqual(sessionsGo.data.map((s) => s.id).sort(), sessionsTs.data.map((s) => s.id).sort());

        // password changed on Go works on TypeScript
        const changed = await goC.client.changePassword({ currentPassword: "password1234", newPassword: "new-password-5678" });
        assert.equal(changed.error, null, JSON.stringify(changed.error));
        const tsC2 = makeClient(servers.ts);
        assert.equal((await tsC2.client.signIn.email({ email, password: "password1234" })).error.status, 401);
        assert.equal((await tsC2.client.signIn.email({ email, password: "new-password-5678" })).error, null);

        // revoking on TypeScript signs the Go session out
        assert.equal((await tsC2.client.revokeSessions()).error, null);
        assert.equal(await sessionOf(goC), null);
      });

      test("verification rows: reset token issued by TypeScript is redeemed on Go", async (t) => {
        if (!servers) return t.skip(`${db.name} unavailable`);
        const email = uniqueEmail("reset");
        const tsC = makeClient(servers.ts);
        assert.equal((await tsC.client.signUp.email({ email, password: "password1234", name: "Reset User" })).error, null);
        assert.equal((await tsC.client.requestPasswordReset({ email, redirectTo: "/reset" })).error, null);
        const mail = await lastEmail(servers.ts, email, "reset-password");
        const goC = makeClient(servers.go);
        const reset = await goC.client.resetPassword({ newPassword: "reset-password-1", token: mail.token });
        assert.equal(reset.error, null, JSON.stringify(reset.error));
        assert.equal((await makeClient(servers.ts).client.signIn.email({ email, password: "reset-password-1" })).error, null);
        // the token was consumed (deleted) by Go
        const again = await makeClient(servers.ts).client.resetPassword({ newPassword: "x-password-2", token: mail.token });
        assert.equal(again.error?.code, "INVALID_TOKEN");
      });

      test("user signed up on TypeScript signs in on Go; delete on Go removes it for TypeScript", async (t) => {
        if (!servers) return t.skip(`${db.name} unavailable`);
        const email = uniqueEmail("tsfirst");
        const tsC = makeClient(servers.ts);
        assert.equal((await tsC.client.signUp.email({ email, password: "password1234", name: "TS First" })).error, null);
        const goC = makeClient(servers.go);
        const signIn = await goC.client.signIn.email({ email, password: "password1234" });
        assert.equal(signIn.error, null, JSON.stringify(signIn.error));
        const accounts = await goC.client.listAccounts();
        assert.equal(accounts.data.length, 1);
        assert.equal(accounts.data[0].providerId, "credential");
        assert.equal((await goC.client.deleteUser({ password: "password1234" })).error, null);
        assert.equal((await makeClient(servers.ts).client.signIn.email({ email, password: "password1234" })).error.status, 401);
      });
    });
  }
}
