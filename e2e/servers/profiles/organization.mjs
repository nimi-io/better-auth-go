// Organization profile (mirrors e2e/goserver/profile_organization.go): teams and dynamic
// access control enabled; invitation emails are recorded as type "invitation" with the
// invitation id as token.
import { organization } from "better-auth/plugins/organization";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements, adminAc, ownerAc, memberAc } from "better-auth/plugins/organization/access";

export default async function (options, { record }) {
  const ac = createAccessControl(defaultStatements);
  options.plugins = [
    ...(options.plugins ?? []),
    organization({
      ac,
      roles: { owner: ownerAc, admin: adminAc, member: memberAc },
      teams: { enabled: true, maximumTeams: 5 },
      dynamicAccessControl: { enabled: true },
      invitationLimit: 5,
      sendInvitationEmail: async (data) => {
        record("invitation", data.email, "", data.id);
      },
    }),
  ];
}
