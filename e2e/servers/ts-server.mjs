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

if (profile === "oauth") {
  // Route provider hosts to the mock IdP: https://host/path -> <IDP_URL>/host/path.
  const idp = process.env.IDP_URL;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const u = new URL(typeof input === "string" || input instanceof URL ? String(input) : input.url);
    if (u.protocol === "https:" && idp) {
      const target = `${idp}/${u.host}${u.pathname}${u.search}`;
      if (input instanceof Request) return realFetch(new Request(target, input), init);
      return realFetch(target, init);
    }
    return realFetch(input, init);
  };
  options.socialProviders = {
    github: { clientId: "gh-client", clientSecret: "gh-secret" },
    google: { clientId: "google-client", clientSecret: "google-secret" },
    // The remaining providers are only exercised for authorization-URL parity.
    apple: { clientId: "apple-client", clientSecret: "apple-secret" },
    atlassian: { clientId: "atlassian-client", clientSecret: "atlassian-secret" },
    cloudflare: { clientId: "cloudflare-client", clientSecret: "cloudflare-secret" },
    cognito: { clientId: "cognito-client", clientSecret: "cognito-secret", domain: "auth.example.com", region: "us-east-1", userPoolId: "us-east-1_pool" },
    discord: { clientId: "discord-client", clientSecret: "discord-secret" },
    dropbox: { clientId: "dropbox-client", clientSecret: "dropbox-secret" },
    facebook: { clientId: "facebook-client", clientSecret: "facebook-secret" },
    figma: { clientId: "figma-client", clientSecret: "figma-secret" },
    gitlab: { clientId: "gitlab-client", clientSecret: "gitlab-secret" },
    huggingface: { clientId: "huggingface-client", clientSecret: "huggingface-secret" },
    kakao: { clientId: "kakao-client", clientSecret: "kakao-secret" },
    kick: { clientId: "kick-client", clientSecret: "kick-secret" },
    line: { clientId: "line-client", clientSecret: "line-secret" },
    linear: { clientId: "linear-client", clientSecret: "linear-secret" },
    linkedin: { clientId: "linkedin-client", clientSecret: "linkedin-secret" },
    microsoft: { clientId: "microsoft-client", clientSecret: "microsoft-secret", tenantId: "e2e-tenant" },
    naver: { clientId: "naver-client", clientSecret: "naver-secret" },
    notion: { clientId: "notion-client", clientSecret: "notion-secret" },
    paybin: { clientId: "paybin-client", clientSecret: "paybin-secret" },
    paypal: { clientId: "paypal-client", clientSecret: "paypal-secret" },
    polar: { clientId: "polar-client", clientSecret: "polar-secret" },
    railway: { clientId: "railway-client", clientSecret: "railway-secret" },
    reddit: { clientId: "reddit-client", clientSecret: "reddit-secret" },
    roblox: { clientId: "roblox-client", clientSecret: "roblox-secret" },
    salesforce: { clientId: "salesforce-client", clientSecret: "salesforce-secret" },
    slack: { clientId: "slack-client", clientSecret: "slack-secret" },
    spotify: { clientId: "spotify-client", clientSecret: "spotify-secret" },
    tiktok: { clientId: "tiktok-client", clientSecret: "tiktok-secret", clientKey: "tiktok-key" },
    twitch: { clientId: "twitch-client", clientSecret: "twitch-secret" },
    twitter: { clientId: "twitter-client", clientSecret: "twitter-secret" },
    vercel: { clientId: "vercel-client", clientSecret: "vercel-secret" },
    vk: { clientId: "vk-client", clientSecret: "vk-secret" },
    wechat: { clientId: "wechat-client", clientSecret: "wechat-secret" },
    zoom: { clientId: "zoom-client", clientSecret: "zoom-secret" },
  };
}

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
