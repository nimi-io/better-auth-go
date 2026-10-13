// Have I Been Pwned profile (mirrors e2e/goserver/profile_haveibeenpwned.go): the range API
// is answered by a patched fetch; "password123" and "breached-password" are breached.
// /__test/pwned returns the last outbound request.
import { createHash } from "node:crypto";
import { haveIBeenPwned } from "better-auth/plugins";

let last = null;
const breached = ["password123", "breached-password"];

export const testRoutes = {
  "/__test/pwned": async (_req, res) => res.end(JSON.stringify(last)),
};

export default async function (options) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    if (!url.startsWith("https://api.pwnedpasswords.com/range/")) return realFetch(input, init);
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    last = { url, addPadding: headers.get("add-padding"), userAgent: headers.get("user-agent") };
    const prefix = url.slice("https://api.pwnedpasswords.com/range/".length);
    let body = "";
    for (const pw of breached) {
      const h = createHash("sha1").update(pw).digest("hex").toUpperCase();
      if (h.startsWith(prefix)) body += `${h.slice(5)}:5\r\n`;
    }
    body += "0000000000000000000000000000000000A:0";
    return new Response(body, { status: 200, headers: { "content-type": "text/plain" } });
  };
  options.plugins = [...(options.plugins ?? []), haveIBeenPwned()];
}
