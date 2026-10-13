// Organization plugin parity: the official organizationClient against the Go server and the
// reference TypeScript server (profile "organization": teams + dynamic access control);
// normalised transcripts must be identical.
//
// The TypeScript server stores data in SQLite, which returns null for never-written nullable
// columns (logo, metadata, teamId, updatedAt, image, ...), while the Go server's memory adapter
// omits them; null-valued keys are therefore dropped from both transcripts before comparing.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { organizationClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch, lastEmail } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers("organization"); });
after(async () => { await servers?.stop(); });

const orgClient = (server) => makeClient(server, { plugins: [organizationClient({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } })] });

function dropNulls(value) {
  if (Array.isArray(value)) return value.map(dropNulls);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) if (v !== null) out[k] = dropNulls(v);
    return out;
  }
  return value;
}

/** Runs a scenario on both servers, dropping null-valued keys from the transcript. */
async function dualOrg(scenario) {
  return dual(servers, async (server, t) => {
    await scenario(server, t);
    for (let i = 0; i < t.length; i++) {
      const e = t[i];
      t[i] = { ...e, data: e.data === null ? null : dropNulls(e.data) };
    }
  });
}

const json = (body) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
let seq = 0;
const unique = (p) => `${p}-${process.pid}-${++seq}`;

test("organization lifecycle: create, slug check, list, get, set-active, update, delete", async () => {
  const slug = unique("acme");
  const t = await dualOrg(async (server, t) => {
    const a = orgClient(server);
    const b = orgClient(server);
    await record(t, "owner sign-up", a, () => a.client.signUp.email({ email: "owner@example.com", password: "password1234", name: "Owner" }));
    await record(t, "other sign-up", b, () => b.client.signUp.email({ email: "other@example.com", password: "password1234", name: "Other" }));
    await record(t, "create missing name", a, () => a.client.organization.create({ slug: "x" }));
    const anon = orgClient(server);
    await record(t, "create unauthenticated", anon, () => anon.client.organization.create({ name: "X", slug: "x" }));
    const org = await record(t, "create", a, () => a.client.organization.create({ name: "Acme", slug, metadata: { plan: "pro" }, logo: "https://logo.example/a.png" }));
    await record(t, "session has active org", a, () => a.client.getSession());
    await record(t, "create duplicate slug", a, () => a.client.organization.create({ name: "Acme 2", slug }));
    await record(t, "check slug taken", a, () => a.client.organization.checkSlug({ slug }));
    await record(t, "check slug free", a, () => a.client.organization.checkSlug({ slug: slug + "-free" }));
    await record(t, "create second keep active", a, () => a.client.organization.create({ name: "Second", slug: slug + "-2", keepCurrentActiveOrganization: true }));
    await record(t, "list", a, () => a.client.organization.list());
    await record(t, "get full (active)", a, () => a.client.organization.getFullOrganization());
    await record(t, "get full by slug", a, () => a.client.organization.getFullOrganization({ query: { organizationSlug: slug + "-2", membersLimit: 1 } }));
    await record(t, "get full not member", b, () => b.client.organization.getFullOrganization({ query: { organizationId: org.data.id } }));
    await record(t, "get full none", b, () => b.client.organization.getFullOrganization());
    await record(t, "set active by slug", a, () => a.client.organization.setActive({ organizationSlug: slug + "-2" }));
    await record(t, "set active not member", b, () => b.client.organization.setActive({ organizationId: org.data.id }));
    await record(t, "set active null", a, () => a.client.organization.setActive({ organizationId: null }));
    await record(t, "set active null again", a, () => a.client.organization.setActive({ organizationId: null }));
    await record(t, "set active by id", a, () => a.client.organization.setActive({ organizationId: org.data.id }));
    await record(t, "update", a, () => a.client.organization.update({ data: { name: "Acme Inc", metadata: { plan: "enterprise" } } }));
    await record(t, "update slug taken", a, () => a.client.organization.update({ data: { slug: slug + "-2" } }));
    await record(t, "update not member", b, () => b.client.organization.update({ organizationId: org.data.id, data: { name: "Hijack" } }));
    await record(t, "update invalid", a, () => a.client.organization.update({ data: { name: "" } }));
    await recordFetch(t, "get-organization", a, "/organization/get-organization", {});
    await record(t, "delete not member", b, () => b.client.organization.delete({ organizationId: org.data.id }));
    await record(t, "delete", a, () => a.client.organization.delete({ organizationId: org.data.id }));
    await record(t, "session cleared active org", a, () => a.client.getSession());
    await record(t, "list after delete", a, () => a.client.organization.list());
  });
  assert.equal(t[4].data.slug, slug);
  assert.equal(t[4].data.members[0].role, "owner");
});

test("members and invitations", async () => {
  const membersSlug = unique("members");
  const t = await dualOrg(async (server, t) => {
    const a = orgClient(server);
    const b = orgClient(server);
    const c = orgClient(server);
    await record(t, "owner sign-up", a, () => a.client.signUp.email({ email: "mowner@example.com", password: "password1234", name: "Owner" }));
    await record(t, "b sign-up", b, () => b.client.signUp.email({ email: "mb@example.com", password: "password1234", name: "B" }));
    await record(t, "c sign-up", c, () => c.client.signUp.email({ email: "mc@example.com", password: "password1234", name: "C" }));
    const org = await record(t, "create", a, () => a.client.organization.create({ name: "Members", slug: membersSlug }));
    await record(t, "invite invalid email", a, () => a.client.organization.inviteMember({ email: "nope", role: "member" }));
    await record(t, "invite unknown role", a, () => a.client.organization.inviteMember({ email: "mb@example.com", role: "wizard" }));
    const inv = await record(t, "invite b", a, () => a.client.organization.inviteMember({ email: "MB@example.com", role: "admin" }));
    const mail = await lastEmail(server, "mb@example.com", "invitation");
    t.push({ name: "invitation email", match: mail?.token === inv.data.id });
    await record(t, "invite b again", a, () => a.client.organization.inviteMember({ email: "mb@example.com", role: "admin" }));
    await record(t, "invite b resend", a, () => a.client.organization.inviteMember({ email: "mb@example.com", role: "admin", resend: true }));
    const invC = await record(t, "invite c", a, () => a.client.organization.inviteMember({ email: "mc@example.com", role: ["member", "admin"] }));
    await record(t, "invite not member", b, () => b.client.organization.inviteMember({ email: "x@example.com", role: "member", organizationId: org.data.id }));
    await record(t, "list invitations", a, () => a.client.organization.listInvitations());
    await record(t, "list user invitations unverified", b, () => b.client.organization.listUserInvitations());
    await record(t, "get invitation", b, () => b.client.organization.getInvitation({ query: { id: inv.data.id } }));
    await record(t, "get invitation wrong recipient", c, () => c.client.organization.getInvitation({ query: { id: inv.data.id } }));
    await record(t, "get invitation unknown", b, () => b.client.organization.getInvitation({ query: { id: "missing" } }));
    await record(t, "accept wrong recipient", c, () => c.client.organization.acceptInvitation({ invitationId: inv.data.id }));
    const accepted = await record(t, "accept", b, () => b.client.organization.acceptInvitation({ invitationId: inv.data.id }));
    await record(t, "accept again", b, () => b.client.organization.acceptInvitation({ invitationId: inv.data.id }));
    await record(t, "b session active org", b, () => b.client.getSession());
    await record(t, "reject c", c, () => c.client.organization.rejectInvitation({ invitationId: invC.data.id }));
    await record(t, "reject again", c, () => c.client.organization.rejectInvitation({ invitationId: invC.data.id }));
    const invC2 = await record(t, "re-invite c", a, () => a.client.organization.inviteMember({ email: "mc@example.com", role: "member" }));
    await record(t, "cancel c", a, () => a.client.organization.cancelInvitation({ invitationId: invC2.data.id }));
    await record(t, "list members", a, () => a.client.organization.listMembers({ query: { sortBy: "createdAt", sortDirection: "asc" } }));
    await record(t, "list members paginated", a, () => a.client.organization.listMembers({ query: { limit: 1, offset: 1 } }));
    await record(t, "list members filtered", a, () => a.client.organization.listMembers({ query: { filterField: "role", filterOperator: "eq", filterValue: "admin" } }));
    await record(t, "list members bad operator", a, () => a.client.organization.listMembers({ query: { filterField: "role", filterOperator: "like", filterValue: "x" } }));
    await record(t, "active member", b, () => b.client.organization.getActiveMember());
    await record(t, "active member role", b, () => b.client.organization.getActiveMemberRole());
    await record(t, "member role of other", a, () => a.client.organization.getActiveMemberRole({ query: { userId: accepted.data.member.userId } }));
    await record(t, "admin cannot promote to owner", b, () => b.client.organization.updateMemberRole({ memberId: accepted.data.member.id, role: "owner" }));
    await record(t, "update role unknown", a, () => a.client.organization.updateMemberRole({ memberId: accepted.data.member.id, role: "wizard" }));
    await record(t, "update role", a, () => a.client.organization.updateMemberRole({ memberId: accepted.data.member.id, role: ["member", "admin"] }));
    await record(t, "owner cannot leave", a, () => a.client.organization.leave({ organizationId: org.data.id }));
    await record(t, "remove member by email", a, () => a.client.organization.removeMember({ memberIdOrEmail: "mb@example.com" }));
    await record(t, "remove unknown member", a, () => a.client.organization.removeMember({ memberIdOrEmail: "missing-member" }));
    await record(t, "removed user has no orgs", b, () => b.client.organization.list());
    await record(t, "has permission owner", a, () => a.client.organization.hasPermission({ permissions: { organization: ["delete"], member: ["create"] } }));
    await recordFetch(t, "has permission both", a, "/organization/has-permission", json({ permission: { member: ["create"] }, permissions: { member: ["create"] } }));
    await recordFetch(t, "has permission none", a, "/organization/has-permission", json({}));
  });
  assert.equal(t.find((e) => e.name === "invitation email").match, true);
});

test("teams", async () => {
  const teamsSlug = unique("teams");
  await dualOrg(async (server, t) => {
    const a = orgClient(server);
    const b = orgClient(server);
    await record(t, "owner sign-up", a, () => a.client.signUp.email({ email: "towner@example.com", password: "password1234", name: "Owner" }));
    await record(t, "b sign-up", b, () => b.client.signUp.email({ email: "tb@example.com", password: "password1234", name: "B" }));
    const org = await record(t, "create", a, () => a.client.organization.create({ name: "Teams", slug: teamsSlug }));
    await record(t, "list teams (default)", a, () => a.client.organization.listTeams());
    const team = await record(t, "create team", a, () => a.client.organization.createTeam({ name: "Engineering" }));
    await recordFetch(t, "create team invalid", a, "/organization/create-team", json({ name: 5 }));
    await record(t, "update team", a, () => a.client.organization.updateTeam({ teamId: team.data.id, data: { name: "Eng" } }));
    await record(t, "update team unknown", a, () => a.client.organization.updateTeam({ teamId: "missing", data: { name: "X" } }));
    const inv = await record(t, "invite b to team", a, () => a.client.organization.inviteMember({ email: "tb@example.com", role: "member", teamId: team.data.id }));
    await record(t, "invite bad team id", a, () => a.client.organization.inviteMember({ email: "tz@example.com", role: "member", teamId: "a,b" }));
    await record(t, "accept team invitation", b, () => b.client.organization.acceptInvitation({ invitationId: inv.data.id }));
    await record(t, "b session active team", b, () => b.client.getSession());
    await record(t, "list team members", b, () => b.client.organization.listTeamMembers());
    await record(t, "list user teams", b, () => b.client.organization.listUserTeams());
    await record(t, "list user teams of other (forbidden)", b, () => b.client.organization.listUserTeams({ query: { userId: org.data.members[0].userId } }));
    await record(t, "set active team", a, () => a.client.organization.setActiveTeam({ teamId: team.data.id }));
    await record(t, "set active team null", a, () => a.client.organization.setActiveTeam({ teamId: null }));
    await record(t, "set active team not member", a, () => a.client.organization.setActiveTeam({ teamId: team.data.id }));
    await record(t, "add team member", a, () => a.client.organization.addTeamMember({ teamId: team.data.id, userId: org.data.members[0].userId }));
    await record(t, "add team member again", a, () => a.client.organization.addTeamMember({ teamId: team.data.id, userId: org.data.members[0].userId }));
    await record(t, "add team member not allowed", b, () => b.client.organization.addTeamMember({ teamId: team.data.id, userId: org.data.members[0].userId }));
    await record(t, "remove team member", a, () => a.client.organization.removeTeamMember({ teamId: team.data.id, userId: org.data.members[0].userId }));
    await record(t, "remove team member again", a, () => a.client.organization.removeTeamMember({ teamId: team.data.id, userId: org.data.members[0].userId }));
    await record(t, "full org with teams", a, () => a.client.organization.getFullOrganization());
    for (let i = 0; i < 4; i++) await record(t, `create team ${i}`, a, () => a.client.organization.createTeam({ name: `T${i}` }));
    await record(t, "remove team", a, () => a.client.organization.removeTeam({ teamId: team.data.id }));
    await record(t, "remove team unknown", a, () => a.client.organization.removeTeam({ teamId: team.data.id }));
    await record(t, "list teams", a, () => a.client.organization.listTeams());
  });
});

test("dynamic access control", async () => {
  const dacSlug = unique("dac");
  await dualOrg(async (server, t) => {
    const a = orgClient(server);
    const b = orgClient(server);
    await record(t, "owner sign-up", a, () => a.client.signUp.email({ email: "downer@example.com", password: "password1234", name: "Owner" }));
    await record(t, "b sign-up", b, () => b.client.signUp.email({ email: "db@example.com", password: "password1234", name: "B" }));
    await record(t, "create", a, () => a.client.organization.create({ name: "DAC", slug: dacSlug }));
    await record(t, "create role predefined name", a, () => a.client.organization.createRole({ role: "Admin", permission: { member: ["update"] } }));
    await record(t, "create role invalid resource", a, () => a.client.organization.createRole({ role: "x", permission: { spaceship: ["fly"] } }));
    const role = await record(t, "create role", a, () => a.client.organization.createRole({ role: "Sales", permission: { member: ["update"] } }));
    await record(t, "create role duplicate", a, () => a.client.organization.createRole({ role: "sales", permission: { member: ["update"] } }));
    await record(t, "list roles", a, () => a.client.organization.listRoles());
    await record(t, "get role by name", a, () => a.client.organization.getRole({ query: { roleName: "sales" } }));
    await record(t, "get role by id", a, () => a.client.organization.getRole({ query: { roleId: role.data.roleData.id } }));
    await record(t, "get role unknown", a, () => a.client.organization.getRole({ query: { roleName: "nope" } }));
    await record(t, "update role", a, () => a.client.organization.updateRole({ roleName: "sales", data: { permission: { member: ["update", "delete"] }, roleName: "Sellers" } }));
    await record(t, "update role missing selector", a, () => a.client.organization.updateRole({ data: { roleName: "x" } }));
    const inv = await record(t, "invite with custom role", a, () => a.client.organization.inviteMember({ email: "db@example.com", role: "sellers" }));
    const acc = await record(t, "accept", b, () => b.client.organization.acceptInvitation({ invitationId: inv.data.id }));
    await record(t, "custom role has permission", b, () => b.client.organization.hasPermission({ permissions: { member: ["delete"] } }));
    await record(t, "custom role lacks permission", b, () => b.client.organization.hasPermission({ permissions: { organization: ["delete"] } }));
    await record(t, "member cannot list roles", b, () => b.client.organization.listRoles());
    await record(t, "delete assigned role", a, () => a.client.organization.deleteRole({ roleName: "sellers" }));
    await record(t, "delete predefined role", a, () => a.client.organization.deleteRole({ roleName: "owner" }));
    await record(t, "reassign member", a, () => a.client.organization.updateMemberRole({ memberId: acc.data.member.id, role: "member" }));
    await record(t, "delete role", a, () => a.client.organization.deleteRole({ roleName: "sellers" }));
    await record(t, "delete role again", a, () => a.client.organization.deleteRole({ roleName: "sellers" }));
    await record(t, "list roles empty", a, () => a.client.organization.listRoles());
  });
});
