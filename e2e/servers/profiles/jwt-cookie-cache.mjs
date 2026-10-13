import { jwt } from "better-auth/plugins";
export default async function (options) {
  options.session = { cookieCache: { enabled: true, strategy: "jwt", maxAge: 300 } };
  options.plugins = [...(options.plugins ?? []), jwt({ sessionCookieCache: true })];
}
