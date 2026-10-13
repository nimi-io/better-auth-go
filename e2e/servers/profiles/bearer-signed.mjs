import { bearer } from "better-auth/plugins";
export default async function (options) {
  options.plugins = [...(options.plugins ?? []), bearer({ requireSignature: true })];
}
