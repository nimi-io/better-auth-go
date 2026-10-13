// Device authorization profile (mirrors e2e/goserver/profile_device_authorization.go).
import { deviceAuthorization } from "better-auth/plugins";

export const devicePlugin = () =>
  deviceAuthorization({
    expiresIn: "5min",
    interval: "2s",
    verificationUri: "/device?lang=en",
    validateClient: (clientId) => clientId !== "bad-client",
  });

export default async function (options) {
  options.plugins = [...(options.plugins ?? []), devicePlugin()];
}
