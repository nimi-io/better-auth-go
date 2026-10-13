import { customSession, multiSession } from "better-auth/plugins";
export default async function (options) {
  options.plugins = [
    ...(options.plugins ?? []),
    multiSession(),
    customSession(async ({ user, session }) => {
      const [firstName, lastName] = user.name.split(" ");
      return { user: { firstName, lastName, email: user.email }, newData: { message: "Hello, World!" }, session };
    }, undefined, { shouldMutateListDeviceSessionsEndpoint: true }),
  ];
}
