// Captcha profile (mirrors e2e/goserver/profile_captcha.go): Cloudflare Turnstile with the
// siteverify API answered by a patched fetch. "valid-token" passes, "wrong-host" passes
// with another hostname, anything else fails. /__test/captcha returns the last request.
import { captcha } from "better-auth/plugins";

let last = null;
const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export const testRoutes = {
  "/__test/captcha": async (_req, res) => res.end(JSON.stringify(last)),
};

export default async function (options) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    if (url !== SITEVERIFY) return realFetch(input, init);
    const body = typeof init.body === "string" ? init.body : await new Response(init.body ?? input.body).text();
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    last = { url, contentType: headers.get("content-type"), body };
    const token = JSON.parse(body).response;
    const data = token === "valid-token"
      ? { success: true, hostname: "app.example.com", action: "login" }
      : token === "wrong-host"
        ? { success: true, hostname: "evil.example.com", action: "login" }
        : { success: false, "error-codes": ["invalid-input-response"] };
    return new Response(JSON.stringify(data), { status: 200, headers: { "content-type": "application/json" } });
  };
  options.plugins = [
    ...(options.plugins ?? []),
    captcha({
      provider: "cloudflare-turnstile",
      secretKey: "turnstile-secret",
      allowedHostnames: ["app.example.com"],
      expectedAction: "login",
    }),
  ];
}
