import { bearer, jwt } from "better-auth/plugins";
export default async function (options, { baseURL }) {
  options.plugins = [...(options.plugins ?? []), bearer(), jwt({ jwt: { issuer: baseURL, expirationTime: "1h" } })];
}
