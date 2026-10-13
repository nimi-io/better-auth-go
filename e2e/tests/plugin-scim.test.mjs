// SCIM plugin parity (@better-auth/scim 1.7.7): the same SCIM 2.0 traffic runs against the
// Go and TypeScript servers; transcripts (status, SCIM content type, Location headers,
// WWW-Authenticate and normalised bodies) must match. Covers discovery, bearer
// authentication and scopes, Users and Groups CRUD, PATCH, filters, pagination, attribute
// projection, managed connections and RFC 7644 error responses. A shared SQLite database
// checks that SCIM state and managed tokens issued by one implementation work on the other.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { startServers, dual, normalize } from "../lib/harness.mjs";

const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const TOKEN = "e2e-scim-token";
const READ_TOKEN = "e2e-scim-read-token";
const PARTNERS_TOKEN = "e2e-scim-partners-token";

let servers;
before(async () => { servers = await startServers("scim"); });
after(async () => { await servers?.stop(); });

// Managed tokens, credential ids and connection ids are random; keep their shape only.
function scrub(v) {
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) out[k] = scrub(x);
    return out;
  }
  if (typeof v === "string") {
    return v
      .replace(/ba_scim_credential_[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{48}/g, "<managed-token>")
      .replace(/ba_scim_credential_[A-Za-z0-9_-]{32}/g, "<managed-credential>")
      .replace(/ba_scim_connection_[A-Za-z0-9_-]{32}/g, "<managed-connection>")
      .replace(/\/(Users|Groups)\/[A-Za-z0-9]{24,32}/g, "/$1/<id>")
      .replace(/(value eq |id eq )"[A-Za-z0-9]{24,32}"/g, '$1"<id>"');
  }
  return v;
}

function scimClient(server, transcript) {
  const base = `${server.base}/api/auth/scim/v2`;
  return async function request(name, pathname, { method = "GET", token = TOKEN, body, rawBody, contentType, headers = {} } = {}) {
    const h = { accept: "application/scim+json", ...headers };
    if (token) h.authorization = `Bearer ${token}`;
    if (body !== undefined || rawBody !== undefined) h["content-type"] = contentType ?? "application/scim+json";
    const res = await fetch(`${base}${pathname}`, {
      method,
      headers: h,
      body: rawBody ?? (body === undefined ? undefined : JSON.stringify(body)),
    });
    const text = await res.text();
    let data = text;
    try { data = JSON.parse(text); } catch {}
    const location = res.headers.get("location");
    const contentLocation = res.headers.get("content-location");
    transcript.push(scrub({
      name,
      status: res.status,
      contentType: res.headers.get("content-type"),
      wwwAuthenticate: res.headers.get("www-authenticate"),
      location: location ? normalize(location, server.base) : null,
      contentLocation: contentLocation ? normalize(contentLocation, server.base) : null,
      data: normalize(data, server.base),
    }));
    return { res, data };
  };
}

async function serverCall(server, transcript, name, endpoint, body) {
  const res = await fetch(`${server.base}/__test/scim/call`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ endpoint, body }),
  });
  const data = await res.json();
  if (transcript) transcript.push(scrub({ name, data: normalize(data, server.base) }));
  return data;
}

const patch = (...Operations) => ({ schemas: [PATCH], Operations });

test("scim: discovery and authentication", async () => {
  await dual(servers, async (server, t) => {
    const r = scimClient(server, t);
    await r("service provider config", "/ServiceProviderConfig", { token: null });
    await r("schemas", "/Schemas", { token: null });
    await r("user schema", `/Schemas/${USER}`, { token: null });
    await r("enterprise schema", `/Schemas/${encodeURIComponent(ENTERPRISE)}`, { token: null });
    await r("unknown schema", "/Schemas/urn:unknown", { token: null });
    await r("resource types", "/ResourceTypes", { token: null });
    await r("group resource type", "/ResourceTypes/Group", { token: null });
    await r("unknown resource type", "/ResourceTypes/Device", { token: null });
    await r("no token", "/Users", { token: null });
    await r("invalid token", "/Users", { token: "nope" });
    await r("malformed authorization", "/Users", { token: null, headers: { authorization: "Basic abc" } });
    await r("read token lists", "/Users", { token: READ_TOKEN });
    await r("read token cannot write", "/Users", { token: READ_TOKEN, method: "POST", body: { schemas: [USER], userName: "x@example.com" } });
    await r("read token cannot write groups", "/Groups", { token: READ_TOKEN, method: "POST", body: { schemas: [GROUP], displayName: "x" } });
    await r("unsupported media type", "/Users", { method: "POST", rawBody: "userName=x", contentType: "application/x-www-form-urlencoded" });
    await r("invalid json", "/Users", { method: "POST", rawBody: "{not json" });
    await r("trailing json", "/Users", { method: "POST", rawBody: '{"schemas":[]} trailing' });
    await r("empty body", "/Users", { method: "POST", rawBody: "" });
    await r("plain json accepted", "/Users", { method: "POST", contentType: "application/json; charset=utf-8", body: { schemas: [USER], userName: "json@example.com" } });
    await r("unknown route", "/Devices");
  });
});

test("scim: users CRUD, PATCH, filters, pagination and projection", async () => {
  await dual(servers, async (server, t) => {
    const r = scimClient(server, t);
    const ada = await r("create ada", "/Users", { method: "POST", body: {
      schemas: [USER, ENTERPRISE], externalId: "ext-ada", userName: "Ada@Example.com",
      name: { givenName: " Ada ", familyName: "Lovelace", honorificPrefix: "Countess" },
      emails: [{ value: "ADA.work@example.com", type: "Work" }, { value: "ada.home@example.com", type: "home" }],
      phoneNumbers: [{ value: "+1 555 0100", type: "Mobile", primary: "True" }],
      addresses: [{ streetAddress: "1 Analytical Way", locality: "London", type: "work" }],
      roles: [{ value: "admin", display: "Admin" }],
      title: ["Mathematician"], active: "true",
      [ENTERPRISE]: { employeeNumber: "1815", department: "Engines", manager: { value: "babbage", displayName: "Charles" } },
    } });
    const id = ada.data.id;
    await r("create duplicate userName", "/Users", { method: "POST", body: { schemas: [USER], userName: "ada@example.com" } });
    await r("create duplicate externalId", "/Users", { method: "POST", body: { schemas: [USER], userName: "other@example.com", externalId: "ext-ada" } });
    await r("create duplicate email in Better Auth", "/Users", { method: "POST", body: { schemas: [USER], userName: "ada2", emails: [{ value: "ada.work@example.com" }] } });
    const grace = await r("create grace", "/Users", { method: "POST", body: { schemas: [USER], userName: "grace@example.com", displayName: "Grace Hopper", active: false } });
    await r("create alan", "/Users", { method: "POST", body: { schemas: [USER], userName: "alan", emails: [{ value: "alan@example.com", primary: true }, { value: "turing@example.com", type: "work" }] } });
    await r("get ada", `/Users/${id}`);
    await r("get ada attributes", `/Users/${id}?attributes=userName,emails.value,${ENTERPRISE}:department`);
    await r("get ada excluded", `/Users/${id}?excludedAttributes=emails,meta.created,name.givenName`);
    await r("get conflicting projection", `/Users/${id}?attributes=userName&excludedAttributes=emails`);
    await r("get invalid attribute list", `/Users/${id}?attributes=${encodeURIComponent("user Name")}`);
    await r("get unknown", "/Users/does-not-exist");
    await r("list all", "/Users");
    await r("list paginated", "/Users?startIndex=2&count=1");
    await r("list count zero", "/Users?count=0");
    await r("list bad startIndex", "/Users?startIndex=abc");
    await r("list bad count", "/Users?count=1.5");
    await r("filter userName", `/Users?filter=${encodeURIComponent('userName eq "ADA@example.com"')}`);
    await r("filter externalId", `/Users?filter=${encodeURIComponent('externalId eq "ext-ada"')}`);
    await r("filter id", `/Users?filter=${encodeURIComponent(`id eq "${id}"`)}`);
    await r("filter emails.value", `/Users?filter=${encodeURIComponent('emails.value eq "turing@example.com"')}`);
    await r("filter work email", `/Users?filter=${encodeURIComponent('emails[type eq "work"].value eq "ada.work@example.com"')}`);
    await r("filter conjunction", `/Users?filter=${encodeURIComponent('userName eq "ada@example.com" and externalId eq "ext-ada"')}`);
    await r("filter prefixed attribute", `/Users?filter=${encodeURIComponent(`${USER}:userName eq "grace@example.com"`)}`);
    await r("filter unsupported operator", `/Users?filter=${encodeURIComponent('userName co "ada"')}`);
    await r("filter unsupported attribute", `/Users?filter=${encodeURIComponent('title eq "x"')}`);
    await r("filter unquoted value", `/Users?filter=${encodeURIComponent("userName eq ada")}`);
    await r("filter number value", `/Users?filter=${encodeURIComponent("userName eq 5")}`);
    await r("filter malformed", `/Users?filter=${encodeURIComponent('userName eq "ada')}`);
    await r("filter trailing text", `/Users?filter=${encodeURIComponent('userName eq "ada" trailing')}`);
    await r("filter no operator", `/Users?filter=${encodeURIComponent("userName")}`);
    await r("filter bad conjunction", `/Users?filter=${encodeURIComponent('userName eq "a" and ')}`);
    await r("filter with attributes", `/Users?filter=${encodeURIComponent('userName eq "alan"')}&attributes=emails`);
    await r("replace ada", `/Users/${id}`, { method: "PUT", body: {
      schemas: [USER], externalId: "ext-ada", userName: "ada@example.com", displayName: "Ada King",
      emails: [{ value: "ada@example.com", type: "work", primary: true }], active: true,
    } });
    await r("replace unknown", "/Users/nope", { method: "PUT", body: { schemas: [USER], userName: "x@example.com" } });
    await r("patch replace displayName", `/Users/${id}`, { method: "PATCH", body: patch({ op: "Replace", path: "displayName", value: "Ada Byron" }) });
    await r("patch unchanged", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "displayName", value: "Ada Byron" }) });
    await r("patch pathless", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", value: { "name.givenName": "Augusta", title: "Countess", active: "False" } }) });
    await r("patch add email", `/Users/${id}`, { method: "PATCH", body: patch({ op: "add", path: "emails", value: [{ value: "ada.extra@example.com", type: "other", primary: true }] }) });
    await r("patch work email value", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: 'emails[type eq "work"].value', value: "ada.new@example.com" }) });
    await r("patch primary email value", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "emails[primary eq true].value", value: "ada.primary@example.com" }) });
    await r("patch remove email type", `/Users/${id}`, { method: "PATCH", body: patch({ op: "remove", path: 'emails[type eq "work"].value' }) });
    await r("patch phone add", `/Users/${id}`, { method: "PATCH", body: patch({ op: "add", path: "phoneNumbers", value: [{ value: "+44 20", type: "work", primary: true }] }) });
    await r("patch address filter", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: 'addresses[type eq "work"].locality', value: "Cambridge" }) });
    await r("patch enterprise manager", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: `${ENTERPRISE}:manager`, value: "lovelace-manager" }) });
    await r("patch enterprise root", `/Users/${id}`, { method: "PATCH", body: patch({ op: "add", path: ENTERPRISE, value: { costCenter: "CC-1", division: ["R&D"] } }) });
    await r("patch enterprise unsupported key", `/Users/${id}`, { method: "PATCH", body: patch({ op: "add", path: ENTERPRISE, value: { badKey: 1 } }) });
    await r("patch enterprise invalid value", `/Users/${id}`, { method: "PATCH", body: patch({ op: "add", path: ENTERPRISE, value: { costCenter: "" } }) });
    await r("patch remove enterprise", `/Users/${id}`, { method: "PATCH", body: patch({ op: "remove", path: ENTERPRISE }) });
    await r("patch name object", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "name", value: { formatted: "Lady Lovelace", middleName: "King" } }) });
    await r("patch name unsupported", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "name", value: { nickname: "x" } }) });
    await r("patch readonly id", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "id", value: "x" }) });
    await r("patch readonly meta", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "meta.created", value: "x" }) });
    await r("patch unsupported path", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "nickName", value: "x" }) });
    await r("patch bad active", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "active", value: "maybe" }) });
    await r("patch remove without path", `/Users/${id}`, { method: "PATCH", body: patch({ op: "remove" }) });
    await r("patch pathless non-object", `/Users/${id}`, { method: "PATCH", body: patch({ op: "add", value: "x" }) });
    await r("patch bad op", `/Users/${id}`, { method: "PATCH", body: patch({ op: "move", path: "title", value: "x" }) });
    await r("patch bad schema", `/Users/${id}`, { method: "PATCH", body: { schemas: [USER], Operations: [] } });
    await r("patch remove userName", `/Users/${id}`, { method: "PATCH", body: patch({ op: "remove", path: "userName" }) });
    await r("patch invalid email", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "emails", value: [{ value: "nope" }] }) });
    await r("patch emails cannot be removed", `/Users/${id}`, { method: "PATCH", body: patch({ op: "remove", path: "emails" }) });
    await r("patch reactivate", `/Users/${id}`, { method: "PATCH", body: patch({ op: "replace", path: "active", value: true }) });
    await r("patch userName conflict", `/Users/${grace.data.id}`, { method: "PATCH", body: patch({ op: "replace", path: "userName", value: "ADA@example.com" }) });
    await r("get after patches", `/Users/${id}`);
    await r("delete grace", `/Users/${grace.data.id}`, { method: "DELETE" });
    await r("delete grace again", `/Users/${grace.data.id}`, { method: "DELETE" });
    await r("get deleted", `/Users/${grace.data.id}`);
    await r("partners cannot see workforce users", `/Users/${id}`, { token: PARTNERS_TOKEN });
    await r("partners list", "/Users", { token: PARTNERS_TOKEN });
  });
});

test("scim: user validation errors", async () => {
  await dual(servers, async (server, t) => {
    const r = scimClient(server, t);
    const cases = {
      "missing schemas": { userName: "a@example.com" },
      "wrong schema": { schemas: [GROUP], userName: "a@example.com" },
      "duplicated schema": { schemas: [USER, USER], userName: "a@example.com" },
      "missing userName": { schemas: [USER] },
      "blank userName": { schemas: [USER], userName: "  " },
      "userName not email without emails": { schemas: [USER], userName: "plain" },
      "invalid email": { schemas: [USER], userName: "x", emails: [{ value: "not-an-email" }] },
      "multiple primary emails": { schemas: [USER], userName: "x", emails: [{ value: "a@example.com", primary: true }, { value: "b@example.com", primary: true }] },
      "duplicate email types": { schemas: [USER], userName: "x", emails: [{ value: "a@example.com", type: "Work" }, { value: "b@example.com", type: "work" }] },
      "duplicate email tuples": { schemas: [USER], userName: "x", emails: [{ value: "a@example.com" }, { value: "A@example.com" }] },
      "address without value": { schemas: [USER], userName: "x@example.com", addresses: [{ type: "work", primary: true }] },
      "too many phones": { schemas: [USER], userName: "x@example.com", phoneNumbers: Array.from({ length: 11 }, (_, i) => ({ value: `+1 ${i}` })) },
      "enterprise without schema": { schemas: [USER], userName: "x@example.com", [ENTERPRISE]: { department: "R&D" } },
      "manager without value": { schemas: [USER, ENTERPRISE], userName: "x@example.com", [ENTERPRISE]: { manager: { displayName: "Boss" } } },
      "manager array": { schemas: [USER, ENTERPRISE], userName: "y@example.com", [ENTERPRISE]: { manager: [{ value: "m1" }] } },
      "non-boolean active": { schemas: [USER], userName: "x@example.com", active: "yes" },
      "long title": { schemas: [USER], userName: "x@example.com", title: "t".repeat(1025) },
      "array body": [{ schemas: [USER] }],
      "null emails": { schemas: [USER], userName: "x@example.com", emails: null },
      "number userName": { schemas: [USER], userName: 5 },
    };
    for (const [name, body] of Object.entries(cases)) {
      await r(name, "/Users", { method: "POST", body });
    }
    await r("list after validation", "/Users?attributes=userName");
  });
});

test("scim: groups CRUD, membership PATCH and filters", async () => {
  await dual(servers, async (server, t) => {
    const r = scimClient(server, t);
    const u1 = (await r("create u1", "/Users", { method: "POST", body: { schemas: [USER], userName: "g1@example.com", displayName: "Member One" } })).data;
    const u2 = (await r("create u2", "/Users", { method: "POST", body: { schemas: [USER], userName: "g2@example.com" } })).data;
    const u3 = (await r("create u3", "/Users", { method: "POST", body: { schemas: [USER], userName: "g3@example.com" } })).data;
    const g = (await r("create group", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: " Finance ", externalId: "fin", members: [{ value: u1.id }, { value: u2.id, type: "User" }] } })).data;
    await r("create duplicate displayName", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "finance" } });
    await r("create duplicate externalId", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "Other", externalId: "fin" } });
    await r("create invalid member", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "Bad", members: [{ value: "nope" }] } });
    await r("create group member type", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "Bad2", members: [{ value: u1.id, type: "Group" }] } });
    await r("create group wrong schema", "/Groups", { method: "POST", body: { schemas: [USER], displayName: "Bad3" } });
    await r("create group entra legacy schema", "/Groups", { method: "POST", body: { schemas: [GROUP, "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"], displayName: "Legacy" } });
    await r("create group blank name", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "  " } });
    const empty = (await r("create empty group", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "Engineering" } })).data;
    await r("get group", `/Groups/${g.id}`);
    await r("get group without members", `/Groups/${g.id}?excludedAttributes=members`);
    await r("get group members only", `/Groups/${g.id}?attributes=members.value`);
    await r("list groups", "/Groups");
    await r("list groups no members", "/Groups?attributes=displayName");
    await r("filter displayName", `/Groups?filter=${encodeURIComponent('displayName eq "FINANCE"')}`);
    await r("filter group externalId", `/Groups?filter=${encodeURIComponent('externalId eq "fin"')}`);
    await r("filter group userName unsupported", `/Groups?filter=${encodeURIComponent('userName eq "x"')}`);
    await r("patch add member", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "Add", path: "members", value: [{ value: u3.id }] }) });
    await r("patch add existing member", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "add", path: "members", value: [{ value: u3.id }] }) });
    await r("patch remove member value path", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "remove", path: `members[value eq "${u1.id}"]` }) });
    await r("patch remove members list", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "remove", path: "members", value: [{ value: u2.id }] }) });
    await r("patch replace members", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "replace", path: "members", value: [{ value: u1.id }, { value: u2.id }] }) });
    await r("patch rename", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "replace", path: "displayName", value: "Finance Team" }) });
    await r("patch pathless", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "replace", value: { id: g.id, displayName: "Finance Ops", externalId: "fin-ops" } }) });
    await r("patch pathless change id", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "replace", value: { id: "other" } }) });
    await r("patch remove displayName", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "remove", path: "displayName" }) });
    await r("patch unsupported path", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "replace", path: "description", value: "x" }) });
    await r("patch members not array", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "add", path: "members", value: { value: u1.id } }) });
    await r("patch invalid member", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "add", path: "members", value: [{ value: "missing" }] }) });
    await r("patch duplicate displayName", `/Groups/${empty.id}`, { method: "PATCH", body: patch({ op: "replace", path: "displayName", value: "finance ops" }) });
    await r("patch remove all members", `/Groups/${g.id}`, { method: "PATCH", body: patch({ op: "remove", path: "members" }) });
    await r("replace group", `/Groups/${g.id}`, { method: "PUT", body: { schemas: [GROUP], displayName: "Finance", members: [{ value: u3.id }] } });
    await r("delete member user updates group", `/Users/${u3.id}`, { method: "DELETE" });
    await r("group after user delete", `/Groups/${g.id}`);
    await r("delete group", `/Groups/${g.id}`, { method: "DELETE" });
    await r("get deleted group", `/Groups/${g.id}`);
    await r("partners list groups", "/Groups", { token: PARTNERS_TOKEN });
  });
});

test("scim: managed connections", async () => {
  await dual(servers, async (server, t) => {
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const created = await serverCall(server, t, "create managed", "createSCIMManagedConnection", {
      creationRequestId: "managed-request-0001", provisioningDomainId: "tenant-a", actorId: "admin",
      scopes: ["scim.users.read", "scim.users.write"], expiresAt,
    });
    await serverCall(server, t, "create duplicate request", "createSCIMManagedConnection", {
      creationRequestId: "managed-request-0001", provisioningDomainId: "tenant-a", actorId: "admin",
      scopes: ["scim.users.read"], expiresAt,
    });
    await serverCall(server, t, "create past expiry", "createSCIMManagedConnection", {
      creationRequestId: "managed-request-0002", provisioningDomainId: "tenant-a", actorId: "admin",
      scopes: ["scim.users.read"], expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    await serverCall(server, t, "create short request id", "createSCIMManagedConnection", {
      creationRequestId: "short", provisioningDomainId: "tenant-a", actorId: "admin", scopes: ["scim.users.read"], expiresAt,
    });
    const token = created.data.token;
    const connectionId = created.data.connection.connectionId;
    const r = scimClient(server, t);
    await r("managed token creates user", "/Users", { token, method: "POST", body: { schemas: [USER], userName: "managed@example.com" } });
    await r("managed token lacks groups scope", "/Groups", { token });
    await r("managed token wrong secret", "/Users", { token: token.slice(0, -2) + "xx" });
    await serverCall(server, t, "list managed", "listSCIMManagedConnections", { provisioningDomainId: "tenant-a" });
    await serverCall(server, t, "get managed", "getSCIMManagedConnection", { connectionId, provisioningDomainId: "tenant-a" });
    await serverCall(server, t, "get managed wrong tenant", "getSCIMManagedConnection", { connectionId, provisioningDomainId: "tenant-b" });
    const rotated = await serverCall(server, t, "rotate", "rotateSCIMManagedCredential", {
      connectionId, provisioningDomainId: "tenant-a", actorId: "admin", scopes: ["scim.users.read"], expiresAt,
    });
    await r("rotated token reads", "/Users", { token: rotated.data.token });
    await r("rotated token cannot write", "/Users", { token: rotated.data.token, method: "POST", body: { schemas: [USER], userName: "x@example.com" } });
    await serverCall(server, t, "revoke original", "revokeSCIMManagedCredential", {
      connectionId, provisioningDomainId: "tenant-a", credentialId: created.data.credential.credentialId, actorId: "admin",
    });
    await r("revoked token rejected", "/Users", { token });
    await serverCall(server, t, "events", "listSCIMManagedConnectionEvents", { connectionId, provisioningDomainId: "tenant-a" });
    await serverCall(server, t, "decommission", "decommissionSCIMManagedConnection", { connectionId, provisioningDomainId: "tenant-a", actorId: "admin" });
    await r("decommissioned token rejected", "/Users", { token: rotated.data.token });
    await serverCall(server, t, "decommission again", "decommissionSCIMManagedConnection", { connectionId, provisioningDomainId: "tenant-a", actorId: "admin" });
    await serverCall(server, t, "static decommission unknown", "decommissionSCIMConnection", { connectionId: "never-used" });
    await serverCall(server, t, "static decommission new domain", "decommissionSCIMConnection", { connectionId: "never-used-2", provisioningDomainId: "d" });
  });
});

test("scim: shared database across implementations", async (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-scim-"));
  const url = `sqlite:${path.join(dir, "shared.db")}`;
  let shared;
  try {
    shared = await startServers("scim", { env: { DB_URL: url }, envFor: { ts: { MIGRATE: "1" } } });
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  try {
    const { go, ts } = shared;
    const goR = scimClient(go, []);
    const tsR = scimClient(ts, []);
    const created = await goR("create on go", "/Users", { method: "POST", body: { schemas: [USER], userName: "shared@example.com", externalId: "shared-1", emails: [{ value: "shared@example.com", type: "work" }] } });
    assert.equal(created.res.status, 201, JSON.stringify(created.data));
    const fromTs = await tsR("get on ts", `/Users/${created.data.id}`);
    assert.equal(fromTs.res.status, 200, JSON.stringify(fromTs.data));
    assert.deepEqual(normalize(fromTs.data, ts.base), normalize(created.data, go.base));
    const byFilter = await tsR("filter on ts", `/Users?filter=${encodeURIComponent('emails[type eq "work"].value eq "shared@example.com"')}`);
    assert.equal(byFilter.data.totalResults, 1);
    const group = await tsR("group on ts", "/Groups", { method: "POST", body: { schemas: [GROUP], displayName: "Shared", members: [{ value: created.data.id }] } });
    assert.equal(group.res.status, 201, JSON.stringify(group.data));
    const patched = await goR("patch on go", `/Users/${created.data.id}`, { method: "PATCH", body: patch({ op: "replace", path: "displayName", value: "Shared Person" }) });
    assert.equal(patched.res.status, 200, JSON.stringify(patched.data));
    const groupOnGo = await goR("group on go", `/Groups/${group.data.id}`);
    assert.equal(groupOnGo.data.members[0].display, "Shared Person");
    const dupOnTs = await tsR("duplicate on ts", "/Users", { method: "POST", body: { schemas: [USER], userName: "SHARED@example.com" } });
    assert.equal(dupOnTs.res.status, 409);

    // A managed SCIM token issued by one implementation authenticates on the other.
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    for (const [issuer, verifier, vR] of [[ts, go, goR], [go, ts, tsR]]) {
      const issued = await serverCall(issuer, null, "issue", "createSCIMManagedConnection", {
        creationRequestId: `shared-request-${issuer === ts ? "ts" : "go"}-0001`, provisioningDomainId: "shared-tenant",
        actorId: "admin", scopes: ["scim.users.read", "scim.users.write"], expiresAt,
      });
      assert.ok(issued.data?.token, JSON.stringify(issued));
      const vClient = scimClient(verifier, []);
      const ok = await vClient("managed user on verifier", "/Users", { token: issued.data.token, method: "POST", body: { schemas: [USER], userName: `managed-${issuer === ts ? "ts" : "go"}@example.com` } });
      assert.equal(ok.res.status, 201, JSON.stringify(ok.data));
      const bad = await vR("tampered", "/Users", { token: issued.data.token.slice(0, -1) + (issued.data.token.endsWith("A") ? "B" : "A") });
      assert.equal(bad.res.status, 401);
      // revoked on the verifier, rejected on the issuer
      const revoked = await serverCall(verifier, null, "revoke", "revokeSCIMManagedCredential", {
        connectionId: issued.data.connection.connectionId, provisioningDomainId: "shared-tenant",
        credentialId: issued.data.credential.credentialId, actorId: "admin",
      });
      assert.equal(revoked.data?.credentials?.[0]?.status, "revoked", JSON.stringify(revoked));
      const after = await scimClient(issuer, [])("after revoke", "/Users", { token: issued.data.token });
      assert.equal(after.res.status, 401);
    }
  } finally {
    await shared.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
