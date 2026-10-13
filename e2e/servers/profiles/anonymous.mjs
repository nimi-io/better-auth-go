// Anonymous profile (mirrors e2e/goserver/profile_anonymous.go).
import { anonymous } from "better-auth/plugins";

export default async function (options) {
  options.plugins = [...(options.plugins ?? []), anonymous({ generateName: () => "Guest" })];
}
