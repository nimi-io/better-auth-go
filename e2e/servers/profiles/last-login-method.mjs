import { lastLoginMethod } from "better-auth/plugins";
export default async function (options) {
  options.plugins = [...(options.plugins ?? []), lastLoginMethod({ storeInDatabase: true })];
}
