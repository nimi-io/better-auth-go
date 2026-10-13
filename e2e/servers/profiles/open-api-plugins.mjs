// Open API profile with plugins (mirrors e2e/goserver/profile_device_authorization.go).
import { openAPI, username, anonymous, admin, twoFactor } from "better-auth/plugins";
import { devicePlugin } from "./device-authorization.mjs";

export default async function (options) {
  options.plugins = [
    ...(options.plugins ?? []),
    openAPI(),
    devicePlugin(),
    username(),
    anonymous(),
    admin(),
    twoFactor(),
  ];
}
