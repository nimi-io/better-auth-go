// Admin plugin parity: the official adminClient against the Go server and the reference
// TypeScript server (profile "admin"); normalised transcripts must be identical.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { adminClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers("admin"); });
after(async () => { await servers?.stop(); });

const adminOf = (server) => makeClient(server, { plugins: [adminClient()] });

test("user management: create, list, get, set-role, update, remove", async () => {
  const t = await dual(servers, async (server, t) => {
    const a = adminOf(server);
    const u = adminOf(server);
    const me = await record(t, "admin sign-up", a, () => a.client.signUp.email({ email: "root@example.com", password: "password1234", name: "Admin" }));
    await record(t, "user sign-up", u, () => u.client.signUp.email({ email: "plain@example.com", password: "password1234", name: "Plain" }));
    const created = await record(t, "create user", a, () => a.client.admin.createUser({ email: "Created@Example.com", password: "password1234", name: "Created", role: ["user", "editor"], data: { image: "https://img/x.png" } }));
    await record(t, "create duplicate", a, () => a.client.admin.createUser({ email: "created@example.com", password: "password1234", name: "Created" }));
    await record(t, "create invalid email", a, () => a.client.admin.createUser({ email: "nope", password: "password1234", name: "X" }));
    await record(t, "create missing name", a, () => a.client.admin.createUser({ email: "x@example.com" }));
    await record(t, "create forbidden", u, () => u.client.admin.createUser({ email: "y@example.com", password: "password1234", name: "Y" }));
    await record(t, "list users", a, () => a.client.admin.listUsers({ query: { sortBy: "email", sortDirection: "asc" } }));
    await record(t, "list paginated", a, () => a.client.admin.listUsers({ query: { limit: 1, offset: 1, sortBy: "email" } }));
    await record(t, "list search", a, () => a.client.admin.listUsers({ query: { searchValue: "plain", searchField: "email", searchOperator: "starts_with" } }));
    await record(t, "list filter role", a, () => a.client.admin.listUsers({ query: { filterField: "role", filterOperator: "eq", filterValue: "admin" } }));
    await record(t, "list bad operator", a, () => a.client.admin.listUsers({ query: { filterOperator: "like", filterValue: "x" } }));
    await record(t, "list forbidden", u, () => u.client.admin.listUsers({ query: {} }));
    const id = created.data.user.id;
    await record(t, "get user", a, () => a.client.admin.getUser({ query: { id } }));
    await record(t, "get unknown user", a, () => a.client.admin.getUser({ query: { id: "missing" } }));
    await record(t, "set role", a, () => a.client.admin.setRole({ userId: id, role: "admin" }));
    await record(t, "set role invalid body", a, () => a.client.admin.setRole({ userId: id, role: 5 }));
    await record(t, "update user", a, () => a.client.admin.updateUser({ userId: id, data: { name: "Renamed", email: "Renamed@Example.com", role: ["user"] } }));
    await record(t, "update empty", a, () => a.client.admin.updateUser({ userId: id, data: {} }));
    await record(t, "update password", a, () => a.client.admin.updateUser({ userId: id, data: { password: "x" } }));
    await record(t, "set user password", a, () => a.client.admin.setUserPassword({ userId: id, newPassword: "new-password-1234" }));
    await record(t, "set user password empty", a, () => a.client.admin.setUserPassword({ userId: "", newPassword: "" }));
    await record(t, "set user password short", a, () => a.client.admin.setUserPassword({ userId: id, newPassword: "short" }));
    const c = adminOf(server);
    await record(t, "sign in with new password", c, () => c.client.signIn.email({ email: "renamed@example.com", password: "new-password-1234" }));
    await record(t, "has permission (session)", a, () => a.client.admin.hasPermission({ permissions: { user: ["create"], session: ["revoke"] } }));
    await record(t, "has permission (user)", u, () => u.client.admin.hasPermission({ permissions: { user: ["create"] } }));
    await recordFetch(t, "has permission none", a, "/admin/has-permission", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    await recordFetch(t, "has permission both", a, "/admin/has-permission", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ permission: { user: ["list"] }, permissions: { user: ["list"] } }) });
    await recordFetch(t, "has permission singular", a, "/admin/has-permission", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ permission: { user: ["list"] } }) });
    await record(t, "remove self", a, () => a.client.admin.removeUser({ userId: me.data.user.id }));
    await record(t, "remove user", a, () => a.client.admin.removeUser({ userId: id }));
    await record(t, "remove unknown", a, () => a.client.admin.removeUser({ userId: id }));
    await record(t, "removed user session gone", c, () => c.client.getSession());
  });
  assert.equal(t[2].data.user.role, "user,editor");
  assert.equal(t[2].data.user.email, "created@example.com");
  assert.equal(t[7].data.total, 3);
});

test("ban, unban and sessions", async () => {
  const t = await dual(servers, async (server, t) => {
    const a = adminOf(server);
    const u = adminOf(server);
    const me = await record(t, "admin sign-up", a, () => a.client.signUp.email({ email: "root2@example.com", password: "password1234", name: "Admin" }));
    const su = await record(t, "user sign-up", u, () => u.client.signUp.email({ email: "victim@example.com", password: "password1234", name: "Victim" }));
    const id = su.data.user.id;
    await record(t, "list user sessions", a, () => a.client.admin.listUserSessions({ userId: id }));
    await record(t, "ban", a, () => a.client.admin.banUser({ userId: id, banExpiresIn: 3600 }));
    await record(t, "ban self", a, () => a.client.admin.banUser({ userId: me.data.user.id }));
    await record(t, "banned session gone", u, () => u.client.getSession());
    await record(t, "banned sign-in", u, () => u.client.signIn.email({ email: "victim@example.com", password: "password1234" }));
    await record(t, "unban", a, () => a.client.admin.unbanUser({ userId: id }));
    await record(t, "sign-in after unban", u, () => u.client.signIn.email({ email: "victim@example.com", password: "password1234" }));
    const sessions = await record(t, "sessions", a, () => a.client.admin.listUserSessions({ userId: id }));
    await record(t, "revoke session", a, () => a.client.admin.revokeUserSession({ sessionToken: sessions.data.sessions[0].token }));
    await record(t, "revoked session", u, () => u.client.getSession());
    await record(t, "revoke all", a, () => a.client.admin.revokeUserSessions({ userId: id }));
    await record(t, "ban via update", a, () => a.client.admin.updateUser({ userId: id, data: { banned: true, banReason: "x" } }));
    await record(t, "unauthenticated", u, () => u.client.admin.listUsers({ query: {} }));
  });
  assert.equal(t[3].data.user.banned, true);
  assert.equal(t[3].data.user.banReason, "Spamming");
  assert.equal(t[6].error.code, "BANNED_USER");
});

test("impersonation", async () => {
  const t = await dual(servers, async (server, t) => {
    const a = adminOf(server);
    const u = adminOf(server);
    await record(t, "admin sign-up", a, () => a.client.signUp.email({ email: "root3@example.com", password: "password1234", name: "Admin" }));
    const su = await record(t, "user sign-up", u, () => u.client.signUp.email({ email: "target@example.com", password: "password1234", name: "Target" }));
    const other = adminOf(server);
    const so = await record(t, "other admin sign-up", other, () => other.client.signUp.email({ email: "admin2@example.com", password: "password1234", name: "Admin" }));
    await record(t, "impersonate admin", a, () => a.client.admin.impersonateUser({ userId: so.data.user.id }));
    await record(t, "stop without impersonation", a, () => a.client.admin.stopImpersonating());
    await record(t, "impersonate", a, () => a.client.admin.impersonateUser({ userId: su.data.user.id }));
    await record(t, "session while impersonating", a, () => a.client.getSession());
    await record(t, "list sessions as target", a, () => a.client.listSessions());
    await record(t, "impersonated list-users", a, () => a.client.admin.listUsers({ query: {} }));
    await record(t, "stop impersonating", a, () => a.client.admin.stopImpersonating());
    await record(t, "session after stop", a, () => a.client.getSession());
    await record(t, "non-admin impersonate", u, () => u.client.admin.impersonateUser({ userId: so.data.user.id }));
    await recordFetch(t, "stop impersonating unauthenticated", adminOf(server), "/admin/stop-impersonating", { method: "POST" });
  });
  assert.equal(t[5].data.user.email, "target@example.com");
  assert.ok(t[6].data.session.impersonatedBy);
  assert.equal(t[10].data.user.email, "root3@example.com");
});
