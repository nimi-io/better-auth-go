// Shared harness for the e2e suite: starts the Go server and the reference TypeScript
// server with the same profile, provides official better-auth clients with a cookie jar,
// and records normalised transcripts so both implementations can be diffed.
import { spawn, execFileSync } from "node:child_process";
import { mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";
import { createAuthClient } from "better-auth/client";

const here = path.dirname(fileURLToPath(import.meta.url));
const e2eDir = path.resolve(here, "..");
const repoRoot = path.resolve(e2eDir, "..");
const binDir = path.join(e2eDir, ".bin");
const goBin = path.join(binDir, "goserver");

let built = false;
export function buildGoServer() {
  if (built) return;
  mkdirSync(binDir, { recursive: true });
  execFileSync("go", ["build", "-o", goBin, "./e2e/goserver"], { cwd: repoRoot, stdio: "inherit" });
  built = true;
}

let nextPort = 4300 + Math.floor(Math.random() * 500) * 2;

async function waitHealthy(base, proc, name) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) throw new Error(`${name} exited with ${proc.exitCode}`);
    try {
      const r = await fetch(`${base}/__test/health`);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${name} did not become healthy at ${base}`);
}

/** Starts both servers for a profile. Returns { go, ts, stop }. */
export async function startServers(profile = "", { only } = {}) {
  buildGoServer();
  const servers = {};
  const procs = [];
  const want = only ? [only] : ["go", "ts"];
  for (const kind of want) {
    const port = nextPort++;
    const env = { ...process.env, PORT: String(port), PROFILE: profile, NODE_ENV: "test" };
    const proc = kind === "go"
      ? spawn(goBin, [], { env, stdio: ["ignore", "inherit", "inherit"] })
      : spawn(process.execPath, [path.join(e2eDir, "servers/ts-server.mjs")], { env, stdio: ["ignore", "inherit", "inherit"] });
    procs.push(proc);
    const base = `http://127.0.0.1:${port}`;
    await waitHealthy(base, proc, kind);
    servers[kind] = { kind, base, profile };
  }
  return {
    ...servers,
    async stop() {
      for (const p of procs) p.kill();
    },
  };
}

/** A minimal cookie jar emulating a browser for one origin. */
export class CookieJar {
  constructor() { this.cookies = new Map(); }
  apply(setCookies) {
    for (const sc of setCookies) {
      const [nv, ...attrs] = sc.split(";").map((s) => s.trim());
      const idx = nv.indexOf("=");
      const name = nv.slice(0, idx);
      const value = nv.slice(idx + 1);
      const maxAge = attrs.find((a) => a.toLowerCase().startsWith("max-age="));
      if (maxAge && Number(maxAge.split("=")[1]) <= 0) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  header() { return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "); }
  get(name) { return this.cookies.get(name); }
  set(name, value) { this.cookies.set(name, value); }
  delete(name) { this.cookies.delete(name); }
}

/** Creates an official better-auth client bound to a server with its own cookie jar. */
export function makeClient(server, { origin, plugins = [] } = {}) {
  const jar = new CookieJar();
  const state = { last: null };
  const customFetchImpl = async (input, init = {}) => {
    const headers = new Headers(init.headers);
    const cookie = jar.header();
    if (cookie) headers.set("cookie", cookie);
    if (origin !== null) headers.set("origin", origin ?? server.base);
    const res = await fetch(input, { ...init, headers, redirect: "manual" });
    jar.apply(res.headers.getSetCookie());
    state.last = res;
    return res;
  };
  const client = createAuthClient({
    baseURL: server.base,
    plugins,
    fetchOptions: { customFetchImpl },
  });
  return { client, jar, state, server, fetch: customFetchImpl };
}

const ID = /^[A-Za-z0-9]{24,32}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

/** Replaces volatile values (ids, tokens, dates, base URLs) with placeholders. */
export function normalize(value, base) {
  if (value instanceof Date) return "<date>";
  if (Array.isArray(value)) return value.map((v) => normalize(v, base));
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value)) out[k] = normalize(value[k], base);
    return out;
  }
  if (typeof value === "string") {
    let s = value;
    if (base) s = s.split(base).join("<base>");
    if (ISO.test(s)) return "<date>";
    if (ID.test(s)) return "<id>";
    if (JWT.test(s)) return "<jwt>";
    s = s.replace(/token=[^&]+/g, "token=<token>").replace(/\/reset-password\/[A-Za-z0-9]+/g, "/reset-password/<token>");
    return s;
  }
  return value;
}

/** Normalises Set-Cookie headers to name + attributes + value shape. */
export function normalizeSetCookies(setCookies) {
  return setCookies.map((sc) => {
    const [nv, ...attrs] = sc.split(";").map((s) => s.trim());
    const idx = nv.indexOf("=");
    const name = nv.slice(0, idx);
    const raw = nv.slice(idx + 1);
    let shape = raw === "" ? "<empty>" : "<value>";
    try {
      const dec = decodeURIComponent(raw);
      if (/\.[A-Za-z0-9+/]{43}=$/.test(dec)) shape = "<signed>";
    } catch {}
    const a = attrs.filter((x) => !x.toLowerCase().startsWith("expires=")).sort();
    return `${name}=${shape}; ${a.join("; ")}`;
  }).sort();
}

/** Records the result of a client call into a transcript entry. */
export async function record(transcript, name, c, call) {
  const result = await call();
  const res = c.state.last;
  const entry = {
    name,
    status: res?.status,
    data: normalize(result?.data ?? null, c.server.base),
    error: result?.error ? normalize({ status: result.error.status, code: result.error.code, message: result.error.message }, c.server.base) : null,
    setCookie: res ? normalizeSetCookies(res.headers.getSetCookie()) : [],
    location: res?.headers.get("location") ? normalize(res.headers.get("location"), c.server.base) : null,
  };
  transcript.push(entry);
  return result;
}

/** Records a raw fetch (for endpoints not wrapped by the client). */
export async function recordFetch(transcript, name, c, pathname, init = {}) {
  const res = await c.fetch(`${c.server.base}/api/auth${pathname}`, init);
  const text = await res.text();
  let data = text;
  try { data = JSON.parse(text); } catch {}
  transcript.push({
    name,
    status: res.status,
    data: normalize(data, c.server.base),
    setCookie: normalizeSetCookies(res.headers.getSetCookie()),
    location: res.headers.get("location") ? normalize(res.headers.get("location"), c.server.base) : null,
  });
  return { res, data };
}

/** Treats an absent `image` key as null (see dual's `imageNullEqualsAbsent`). */
function nullImage(value) {
  if (Array.isArray(value)) return value.map(nullImage);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value)) out[k] = nullImage(value[k]);
    if ("email" in out && "emailVerified" in out && !("image" in out)) out.image = null;
    return out;
  }
  return value;
}

/**
 * Runs the same scenario against both servers and asserts identical transcripts.
 * `imageNullEqualsAbsent`: the TS in-memory adapter (used when no database is configured)
 * omits never-written columns, while the Go port always stores `image` (null when omitted)
 * so that real and synthetic sign-up responses are indistinguishable. SQL-backed TS
 * deployments return null too.
 */
export async function dual(servers, scenario, { imageNullEqualsAbsent = false } = {}) {
  const transcripts = {};
  for (const kind of ["go", "ts"]) {
    const t = [];
    await scenario(servers[kind], t);
    transcripts[kind] = imageNullEqualsAbsent ? nullImage(t) : t;
  }
  const diffs = [];
  const n = Math.max(transcripts.go.length, transcripts.ts.length);
  for (let i = 0; i < n; i++) {
    const g = transcripts.go[i];
    const s = transcripts.ts[i];
    try {
      assert.deepEqual(g, s);
    } catch {
      diffs.push(`step ${i} "${(g ?? s)?.name}"\n  go: ${JSON.stringify(g)}\n  ts: ${JSON.stringify(s)}`);
    }
  }
  if (diffs.length) {
    assert.fail(`Go and TypeScript transcripts differ:\n${diffs.join("\n")}`);
  }
  return transcripts.go;
}

export async function lastEmail(server, to, type) {
  const r = await fetch(`${server.base}/__test/email?to=${encodeURIComponent(to ?? "")}&type=${encodeURIComponent(type ?? "")}`);
  return r.json();
}

export function uniqueEmail(prefix = "user") {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}@example.com`;
}
