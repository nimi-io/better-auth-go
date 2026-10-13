// Admin profile (mirrors e2e/goserver/profile_admin.go): users named "Admin" get the admin
// role on sign-up.
import { admin } from "better-auth/plugins";

export default async function (options) {
  options.plugins = [...(options.plugins ?? []), admin({ defaultBanReason: "Spamming" })];
  options.databaseHooks = {
    user: {
      create: {
        before: async (user) => (user.name === "Admin" ? { data: { ...user, role: "admin" } } : undefined),
      },
    },
  };
}
