import { jwt } from "better-auth/plugins";
export default async function (options) {
  options.plugins = [...(options.plugins ?? []), jwt({ jwks: { keyPairConfig: { alg: "ES256" }, jwksPath: "/.well-known/jwks.json" } })];
}
