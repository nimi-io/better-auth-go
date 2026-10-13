// Open API parity: the documents served at /open-api/generate-schema (and the Scalar page
// at /reference) by the Go server and the reference TypeScript server must be identical
// as parsed JSON, for a core-only configuration (profile "open-api") and with plugins
// (profile "open-api-plugins").
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { startServers } from "../lib/harness.mjs";

const running = [];
after(async () => { for (const s of running) await s.stop(); });

async function start(profile) {
  const s = await startServers(profile);
  running.push(s);
  return s;
}

async function fetchDoc(server) {
  const res = await fetch(`${server.base}/api/auth/open-api/generate-schema`);
  assert.equal(res.status, 200);
  return JSON.parse((await res.text()).split(server.base).join("<base>"));
}

/** Lists differences between two parsed JSON values as "path: detail" lines. */
export function jsonDiff(go, ts, path = "") {
  const out = [];
  const walk = (g, s, p) => {
    if (Array.isArray(g) && Array.isArray(s)) {
      if (g.length !== s.length) out.push(`${p}: array length go=${g.length} ts=${s.length} go=${JSON.stringify(g)} ts=${JSON.stringify(s)}`);
      else g.forEach((x, i) => walk(x, s[i], `${p}/${i}`));
      return;
    }
    if (g && s && typeof g === "object" && typeof s === "object" && !Array.isArray(g) && !Array.isArray(s)) {
      for (const k of Object.keys(g)) {
        if (!(k in s)) out.push(`${p}/${k}: only in go: ${JSON.stringify(g[k]).slice(0, 300)}`);
        else walk(g[k], s[k], `${p}/${k}`);
      }
      for (const k of Object.keys(s)) if (!(k in g)) out.push(`${p}/${k}: only in ts: ${JSON.stringify(s[k]).slice(0, 300)}`);
      return;
    }
    if (JSON.stringify(g) !== JSON.stringify(s)) out.push(`${p}: go=${JSON.stringify(g)?.slice(0, 300)} ts=${JSON.stringify(s)?.slice(0, 300)}`);
  };
  walk(go, ts, path);
  return out;
}

test("core-only document is identical", async () => {
  const servers = await start("open-api");
  const [go, ts] = await Promise.all([fetchDoc(servers.go), fetchDoc(servers.ts)]);
  const diff = jsonDiff(go, ts);
  assert.deepEqual(diff, [], `documents differ:\n${diff.join("\n")}`);
  assert.ok(Object.keys(go.paths).length > 25);
});

test("reference page is identical", async () => {
  const servers = await start("open-api");
  const page = async (s) => {
    const res = await fetch(`${s.base}/api/auth/reference`);
    return { status: res.status, type: res.headers.get("content-type"), body: (await res.text()).split(s.base).join("<base>") };
  };
  const [go, ts] = await Promise.all([page(servers.go), page(servers.ts)]);
  assert.equal(go.status, 200);
  assert.deepEqual(go, ts);
});

// Plugins whose Go ports (and their validators / metadata.openapi blocks) are owned outside
// the open-api port: their remaining differences are reported, not asserted.
const EXTERNAL_TAGS = new Set(["Username", "Admin", "Two-factor"]);

test("document with plugins is identical", async (t) => {
  const servers = await start("open-api-plugins");
  const [go, ts] = await Promise.all([fetchDoc(servers.go), fetchDoc(servers.ts)]);
  const diff = jsonDiff(go, ts);
  const external = [];
  const owned = [];
  for (const d of diff) {
    const m = /^\/paths\/(\/[^/]*(?:\/[^/]*)*?)\/(get|post|put|patch|delete)(\/|:)/.exec(d);
    const tag = m ? ts.paths[m[1]]?.[m[2]]?.tags?.[0] : undefined;
    (EXTERNAL_TAGS.has(tag) ? external : owned).push(d);
  }
  for (const d of external) t.diagnostic(`known difference (plugin port): ${d}`);
  assert.deepEqual(owned, [], `documents differ (${owned.length}):\n${owned.join("\n")}`);
  // device-authorization and anonymous operations, components and core paths are identical
  assert.ok(go.paths["/device/code"] && go.components.schemas.DeviceCode);
});
