// Username profile (mirrors e2e/goserver/profile_username.go).
import { username } from "better-auth/plugins";

export default async function (options) {
  options.plugins = [...(options.plugins ?? []), username({ minUsernameLength: 4 })];
}
