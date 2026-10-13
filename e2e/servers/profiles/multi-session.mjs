import { multiSession } from "better-auth/plugins";
export default async function (options) {
  options.plugins = [...(options.plugins ?? []), multiSession({ maximumSessions: 2 })];
}
