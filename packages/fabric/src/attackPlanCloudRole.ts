import type {
  AttackPlan,
} from "./attackPlan.js";

/** Denied push notifications before the user finally accepts one. */
const MFA_DENIALS = 5;

const GRANTED_ROLE =
  "global-administrator";

/**
 * Multi-factor fatigue into a directory role grant.
 *
 * The sixth lesson, and the one every other plan in the library leaves
 * standing. All five of the others reach a host: a process starts, a command
 * line is written, a file is read from a workstation. An analyst who works
 * them learns to pivot to the endpoint, and that habit is right five times
 * out of five, so it stops being a decision.
 *
 * This intrusion never touches an endpoint. There is no process tree to
 * read, no parent image, no command line, and the Endpoint console has
 * nothing to say about it at all. The whole chain lives in identity: a valid
 * password, a user worn down into approving a push, and a role granted to an
 * account that did not have it.
 *
 * It is also the first intrusion here whose containment does not include
 * isolating anything, because there is nothing to isolate. That is not an
 * omission in the scenario; it is the finding.
 */
export const CLOUD_ROLE_PLAN: AttackPlan =
  {
    id: "cloud-role-elevation",
    name: "MFA fatigue into a directory role grant",
    difficulty: "advanced",
    lesson:
      "Not every intrusion reaches a host. This one has no process tree, no command line and nothing on the endpoint at all, the Endpoint console is empty because there is genuinely nothing there. The chain is a valid password, a user worn down into approving a multi-factor prompt, and a privileged role granted to an account that never had it. Watch what changes in the directory, not only what runs.",
    requires: {
      restrictedFile: true,
    },

    techniques: [
      {
        id: "T1621",
        name: "Multi-Factor Authentication Request Generation",
        tactic: "credential_access",
      },
      {
        id: "T1078.004",
        name: "Valid Accounts: Cloud Accounts",
        tactic: "initial_access",
      },
      {
        id: "T1098.003",
        name: "Account Manipulation: Additional Cloud Roles",
        tactic: "persistence",
      },
      {
        id: "T1213",
        name: "Data from Information Repositories",
        tactic: "collection",
      },
    ],

    steps: [
      {
        id: "mfa-pressure",
        title:
          "Repeated multi-factor prompts, all denied",
        techniqueId: "T1621",
        repeat: MFA_DENIALS,
        advanceBy: 2,
        significance: (cast) =>
          `Multi-factor challenge denied for ${cast.subjectAccount.username}, from ${cast.externalIp}. The password is already correct or there would be nothing to challenge.`,
        reasoning: () =>
          "Read what the failures actually say. A wrong password fails before any second factor is involved, so a run of denied multi-factor prompts means the password is already correct and only the user's approval is missing. That inverts the usual reading of failed sign-ins: this is not someone guessing, it is someone waiting. Establish how long the run lasted and whether it ends in an approval, because a burst that stops with no success is a user who held the line, and a burst that ends in one is a compromise with a precise timestamp.",
        build: (cast) => ({
          type: "AUTH_LOGIN_FAILED",
          source: "identity",
          subjectId: cast.subject.id,
          payload: {
            username:
              cast.subjectAccount.username,
            reason: "mfa_failed",
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.externalIp,
          },
        }),
      },
      {
        id: "approved",
        title:
          "One prompt is finally approved",
        techniqueId: "T1078.004",
        advanceBy: 1,
        significance: (cast) =>
          `Successful sign-in for ${cast.subjectAccount.username} from ${cast.externalIp}, immediately after the run of denials. This is the compromise point.`,
        reasoning: () =>
          "This is the moment to anchor scope on, and the one the account holder can usually confirm: they remember being pestered. Everything the account does after this timestamp is suspect and everything before it is probably genuine. Note that nothing about this event is anomalous on its own, valid credential, valid second factor, successful sign-in, which is exactly why it has to be read together with what came immediately before it.",
        build: (cast) => ({
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          actorId: cast.subjectAccount.id,
          subjectId: cast.subject.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            userId: cast.subject.id,
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.externalIp,
          },
        }),
      },
      {
        id: "session",
        title:
          "A session opens against the identity provider",
        techniqueId: "T1078.004",
        advanceBy: 2,
        significance: () =>
          "Session established against the identity provider. No workstation is involved, this is a browser somewhere else.",
        reasoning: () =>
          "Note what this session is not attached to: there is no device on it, because the sign-in did not come from a managed one. That absence is worth naming explicitly, since the reflex at this point is to go and look at the user's workstation, and the workstation has nothing to do with any of this. Carry the session id forward instead; it is what ties the directory changes that follow to this sign-in rather than to the account generally.",
        build: (cast) => ({
          type: "SESSION_STARTED",
          source: "identity",
          actorId: cast.subjectAccount.id,
          subjectId: cast.sessionId,
          payload: {
            sessionId: cast.sessionId,
            accountId:
              cast.subjectAccount.id,
            applicationId:
              cast.identityApplication?.id,
          },
        }),
      },
      {
        id: "role-grant",
        title:
          "The account grants itself an administrative role",
        techniqueId: "T1098.003",
        advanceBy: 4,
        significance: (cast) =>
          `${GRANTED_ROLE} granted to ${cast.subjectAccount.username}, an account that has never held it. This is the finding.`,
        reasoning: () =>
          "This is the step that turns a compromised sign-in into a durable foothold, and it is the one that survives the response most people reach for first: resetting the password removes the attacker's way in and leaves the role exactly where it is. Establish who performed the grant and whether a change ticket exists, then check every other account that holds the same role, an operator who has taken one grant has no reason to have taken only one. Treat the role as the thing to remove, not the session.",
        build: (cast) => ({
          type: "ROLE_GRANTED",
          source: "identity",
          actorId: cast.subjectAccount.id,
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            role: GRANTED_ROLE,
            applicationId:
              cast.identityApplication?.id,
            reason:
              "Self-service role assignment",
          },
        }),
      },
      {
        id: "repository-access",
        title:
          "Restricted material read with the new privilege",
        techniqueId: "T1213",
        advanceBy: 3,
        significance: (cast) =>
          `${cast.targetFile.name} read by ${cast.subjectAccount.username} minutes after the grant. The role is what made it reachable.`,
        reasoning: () =>
          "The access itself is authorised, the role grants it, which is the point of taking the role, so nothing here will have alerted. What makes it the business impact is the sequence: the privilege that permits this read is minutes old and was taken by the account that used it. Check whether this account ever legitimately touched this material before, because a first-time read by a brand-new privilege is a very different claim from an unusual one, and you will be asked which you are making.",
        build: (cast) => ({
          type: "FILE_ACCESSED",
          source: "file_server",
          actorId: cast.subjectAccount.id,
          subjectId: cast.targetFile.id,
          payload: {
            fileId: cast.targetFile.id,
            operation: "read",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-role",
        prompt: () =>
          "Which role was granted to the compromised account?",
        accepted: () => [GRANTED_ROLE],
        hint: "The directory records the grant as its own event, separate from any sign-in.",
        surface: "identity",
        points: 30,
        evidenceStepId: "role-grant",
      },
      {
        id: "q-mfa-count",
        prompt: () =>
          "How many multi-factor challenges were denied before one was approved?",
        accepted: () => [
          String(MFA_DENIALS),
        ],
        hint: "A denied second factor is a different failure reason from a wrong password.",
        surface: "identity",
        points: 25,
        evidenceStepId: "mfa-pressure",
      },
      {
        id: "q-source",
        prompt: () =>
          "Which address were those sign-in attempts made from?",
        accepted: (cast) => [
          cast.externalIp,
        ],
        surface: "siem",
        points: 20,
        evidenceStepId: "approved",
      },
      {
        id: "q-file",
        prompt: () =>
          "Which restricted document was read after the grant?",
        accepted: (cast) => [
          cast.targetFile.name,
        ],
        surface: "siem",
        points: 15,
        evidenceStepId:
          "repository-access",
      },
      {
        id: "q-application",
        prompt: () =>
          "Which application was the role granted in?",
        accepted: (cast) => [
          cast.identityApplication?.name ??
            "Acme Identity Provider",
        ],
        hint: "The grant names the application it applies to.",
        surface: "identity",
        points: 10,
        evidenceStepId: "role-grant",
      },
    ],

    alertTitle: (cast) =>
      `Privileged role granted to ${cast.subjectAccount.username} after repeated multi-factor denials`,
    alertSeverity: "critical",
    alertStepIds: ["role-grant"],

    summary: (cast) =>
      `${cast.subject.displayName}'s account was signed into from ${cast.externalIp} after ${MFA_DENIALS} multi-factor prompts were denied and one was approved. The session granted the account the ${GRANTED_ROLE} role, which it had never held, and read ${cast.targetFile.name} minutes later. No process ran on any workstation at any point: the entire intrusion took place in the directory, and the Endpoint console has nothing to show for it.`,

    containment: {
      // There is no compromised host. That is the lesson, not an omission.
      isolateDevice: false,
      disableAccount: true,
      revokeSession: true,
    },
  };
