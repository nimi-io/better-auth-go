// Open API profile, core endpoints only (mirrors e2e/goserver/profile_device_authorization.go).
import { openAPI } from "better-auth/plugins";

export default async function (options) {
  options.plugins = [...(options.plugins ?? []), openAPI()];
}
