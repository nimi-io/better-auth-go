// Reference TypeScript Better Auth server (better-auth@1.7.7) with the same configuration
// as e2e/goserver/main.go. PROFILE selects the variant.
import { createServer } from "node:http";
import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { toNodeHandler } from "better-auth/node";
import { hashPassword, verifyPassword } from "better-auth/crypto";

const port = Number(process.env.PORT || 4200);
const profile = process.env.PROFILE || "";
const baseURL = `http://127.0.0.1:${port}`;
const emails = [];
const capture = (type) => async ({ user, url, token }) => {
  emails.push({ type, to: user.email, url, token });
};

const options = {
  baseURL,
  secret: "e2e-secret-that-is-long-enough-for-better-auth-tests",
  database: new Database(":memory:"),
  logger: { level: "error" },
  emailAndPassword: { enabled: true, sendResetPassword: capture("reset-password") },
  emailVerification: { sendVerificationEmail: capture("verify-email"), sendOnSignUp: true },
  user: {
    changeEmail: {
      enabled: true,
      sendChangeEmailConfirmation: async ({ user, url, token }) => {
        emails.push({ type: "change-email-confirmation", to: user.email, url, token });
      },
    },
    deleteUser: { enabled: true },
  },
  trustedOrigins: ["http://trusted.example.com"],
  rateLimit: { enabled: false },
  advanced: { disableOriginCheck: false },
  telemetry: { enabled: false },
};
if (["compact", "jwt", "jwe"].includes(profile)) {
  options.session = { cookieCache: { enabled: true, strategy: profile, maxAge: 300 } };
}
if (profile === "secondary") {
  const store = new Map();
  options.secondaryStorage = {
    get: (k) => { const e = store.get(k); if (!e) return null; if (e.exp && e.exp <= Date.now()) { store.delete(k); return null; } return e.v; },
    set: (k, v, ttl) => { store.set(k, { v, exp: ttl ? Date.now() + ttl * 1000 : 0 }); },
    delete: (k) => { store.delete(k); },
    getAndDelete: (k) => { const e = store.get(k); store.delete(k); return e ? e.v : null; },
    increment: (k, ttl) => { const e = store.get(k); const n = (e ? Number(e.v) : 0) + 1; store.set(k, { v: String(n), exp: e?.exp || (ttl ? Date.now() + ttl * 1000 : 0) }); return n; },
  };
}
if (profile === "ratelimit") options.rateLimit = { enabled: true, window: 10, max: 100 };
if (profile === "stateless") delete options.database;
if (profile === "delete-verify") options.user.deleteUser.sendDeleteAccountVerification = capture("delete-account");

const auth = betterAuth(options);
if (options.database) await (await auth.$context).runMigrations();
const handler = toNodeHandler(auth);

createServer(async (req, res) => {
  const url = new URL(req.url, baseURL);
  if (url.pathname.startsWith("/api/auth")) return handler(req, res);
  res.setHeader("content-type", "application/json");
  if (url.pathname === "/__test/email") {
    const to = url.searchParams.get("to"); const type = url.searchParams.get("type");
    const e = [...emails].reverse().find((x) => (!to || x.to.toLowerCase() === to.toLowerCase()) && (!type || x.type === type));
    return res.end(JSON.stringify(e ?? null));
  }
  if (url.pathname === "/__test/hash") return res.end(JSON.stringify({ hash: await hashPassword(url.searchParams.get("password")) }));
  if (url.pathname === "/__test/verify") {
    try { return res.end(JSON.stringify({ ok: await verifyPassword({ hash: url.searchParams.get("hash"), password: url.searchParams.get("password") }), error: "" })); }
    catch (e) { return res.end(JSON.stringify({ ok: false, error: String(e) })); }
  }
  if (url.pathname === "/__test/session") {
    const s = await auth.api.getSession({ headers: new Headers(req.headers) });
    return res.end(JSON.stringify(s));
  }
  if (url.pathname === "/__test/health") return res.end("ok");
  res.statusCode = 404; res.end("null");
}).listen(port, "127.0.0.1", () => console.log(`ts better-auth e2e server on ${baseURL} (profile=${profile})`));
