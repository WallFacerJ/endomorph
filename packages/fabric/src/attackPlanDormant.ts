import type {
  AttackPlan,
} from "./attackPlan.js";

const POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

/**
 * Dormant account revival.
 *
 * The fourth lesson, and the first that is not about authentication at all.
 * Every sign-in in this chain is unremarkable in isolation: valid
 * credential, corporate address, ordinary hour. The three earlier plans all
 * reward an analyst who examines authentication carefully; this one defeats
 * that habit too.
 *
 * The signal happened before any sign-in, an account belonging to someone
 * who no longer works here was re-enabled. It is a single event with no
 * volume behind it, which is precisely why threshold detection misses it.
 */
export const DORMANT_ACCOUNT_PLAN: AttackPlan =
  {
    id: "dormant-account-revival",
    name: "Dormant account revived for access",
    difficulty: "advanced",
    lesson:
      "Watch identity lifecycle, not only authentication. Nothing about the sign-in itself is unusual. The signal happened before it: an account belonging to someone who no longer works here was re-enabled, and a leaver's account has no legitimate reason to come back.",
    requires: {
      windowsWorkstation: true,
      privilegedAccount: true,
      dormantAccount: true,
    },

    techniques: [
      {
        id: "T1087.002",
        name: "Account Discovery: Domain Account",
        tactic: "discovery",
      },
      {
        id: "T1098",
        name: "Account Manipulation",
        tactic: "persistence",
      },
      {
        id: "T1078.002",
        name: "Valid Accounts: Domain Accounts",
        tactic: "defense_evasion",
      },
      {
        id: "T1039",
        name: "Data from Network Shared Drive",
        tactic: "collection",
      },
    ],

    steps: [
      {
        id: "enumerate-accounts",
        title: "Directory filtered to disabled accounts",
        techniqueId: "T1087.002",
        advanceBy: 4,
        significance: () =>
          "Directory enumeration filtered to disabled accounts. Someone is shopping for a credential that nobody watches.",
        reasoning: () =>
          "Enumeration alone is weak evidence; administrators query the directory constantly. The filter is what matters, because there is no routine administrative reason to list only disabled accounts. Treat this as the start of the timeline rather than the finding, and look at what happened next to any account it returned.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "8110",
            image: POWERSHELL,
            commandLine:
              "powershell.exe Get-ADUser -Filter (Enabled -eq $false) -Properties LastLogonDate",
            parentProcessId: "4102",
            parentImage:
              "C:\\Windows\\explorer.exe",
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "reactivate",
        title: "A leaver's account is re-enabled",
        techniqueId: "T1098",
        advanceBy: 6,
        significance: (cast) =>
          `Disabled account ${cast.dormantAccount?.username} re-enabled. It belongs to ${cast.dormantUser?.displayName}, who is no longer active.`,
        reasoning: () =>
          "This is the finding, and it is a single event with no volume behind it, which is exactly why threshold detection misses it. Offboarding runs one way: a leaver account being re-enabled has no legitimate workflow. Establish who performed the change and whether any ticket exists, then treat every subsequent action by that account as attacker activity.",
        build: (cast) => ({
          type: "ACCOUNT_ENABLED",
          source: "identity",
          actorId:
            cast.privilegedAccount?.id ??
            cast.subjectAccount.id,
          subjectId:
            cast.dormantAccount?.id ??
            cast.subjectAccount.id,
          payload: {
            accountId:
              cast.dormantAccount?.id ??
              cast.subjectAccount.id,
            reason:
              "Re-enabled outside the joiners-movers-leavers process.",
          },
        }),
      },
      {
        id: "revived-auth",
        title: "The revived account signs in",
        techniqueId: "T1078.002",
        advanceBy: 2,
        significance: (cast) =>
          `First sign-in on ${cast.dormantAccount?.username} since it was disabled. Corporate address, ordinary hour, valid credential.`,
        reasoning: () =>
          "Judged alone this authentication is unremarkable, and any rule scoring it in isolation will call it benign. It is suspicious only in sequence: a re-enable minutes earlier, on an account with a long gap in its history. Correlate on the account rather than the address, and look at the previous sign-in before this one. The size of that gap is the argument.",
        build: (cast) => ({
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          actorId:
            cast.dormantAccount?.id ??
            cast.subjectAccount.id,
          subjectId:
            cast.dormantUser?.id ??
            cast.subject.id,
          payload: {
            accountId:
              cast.dormantAccount?.id ??
              cast.subjectAccount.id,
            userId:
              cast.dormantUser?.id ??
              cast.subject.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.subjectIp,
          },
        }),
      },
      {
        id: "revived-session",
        title: "Session opens on the revived account",
        techniqueId: "T1078.002",
        advanceBy: 3,
        significance: () =>
          "Session opened on the revived account.",
        reasoning: () =>
          "Note the session id, because containment here is not what the earlier plans trained. Revoking this session and disabling the account again ends the incident; isolating the workstation would leave the credential live.",
        build: (cast) => ({
          type: "SESSION_STARTED",
          source: "identity",
          actorId:
            cast.dormantAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.sessionId,
          payload: {
            sessionId: cast.sessionId,
            accountId:
              cast.dormantAccount?.id ??
              cast.subjectAccount.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
          },
        }),
      },
      {
        id: "share-read",
        title: "Restricted material read by the revived account",
        techniqueId: "T1039",
        advanceBy: 3,
        significance: (cast) =>
          `${cast.targetFile.name} read using the revived account, which has no history against this document at all.`,
        reasoning: () =>
          "A revived account has no baseline to deviate from, so the usual argument is unavailable to you: its entire history is the gap. Compare against the department instead. Does anyone in this person's former team routinely touch this document, and does the access pattern resemble theirs?",
        build: (cast) => ({
          type: "FILE_ACCESSED",
          source: "file_server",
          actorId:
            cast.dormantAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.targetFile.id,
          payload: {
            fileId: cast.targetFile.id,
            operation: "read",
            deviceId: cast.subjectDevice.id,
            accountId:
              cast.dormantAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-revived-account",
        prompt: () =>
          "Who did the re-enabled account belong to? Give their display name.",
        accepted: (cast) => [
          cast.dormantUser?.displayName ??
            cast.subject.displayName,
        ],
        hint: "The alert names the account. Resolve it to the person it belongs to.",
        surface: "identity",
        points: 30,
        evidenceStepId: "reactivate",
      },
      {
        id: "q-who-enabled",
        prompt: () =>
          "Which account performed the re-enable?",
        accepted: (cast) => [
          cast.privilegedAccount
            ?.username ??
            cast.subjectAccount.username,
        ],
        hint: "The actor on a lifecycle event is not the account being changed.",
        surface: "identity",
        points: 25,
        evidenceStepId: "reactivate",
      },
      {
        id: "q-enumeration",
        prompt: () =>
          "Which utility did the attacker use to enumerate the directory?",
        accepted: () => [
          "powershell.exe",
          "powershell",
        ],
        hint: "Read the full command line on the endpoint.",
        surface: "endpoint",
        points: 20,
        evidenceStepId:
          "enumerate-accounts",
      },
      {
        id: "q-revived-file",
        prompt: () =>
          "Which document did the revived account read?",
        accepted: (cast) => [
          cast.targetFile.name,
        ],
        surface: "siem",
        points: 25,
        evidenceStepId: "share-read",
      },
    ],

    alertTitle: (cast) =>
      `Disabled account ${cast.dormantAccount?.username ?? "unknown"} re-enabled and used`,
    alertSeverity: "high",
    alertStepIds: ["reactivate"],

    summary: (cast) =>
      `The privileged account ${cast.privilegedAccount?.username} enumerated disabled directory accounts from ${cast.subjectDevice.hostname}, re-enabled ${cast.dormantAccount?.username} belonging to ${cast.dormantUser?.displayName}, who is no longer active, then signed in with it and read ${cast.targetFile.name}. Every authentication in the chain used a valid credential from a corporate address at an ordinary hour. The only anomalous event is the re-enable itself.`,

    containment: {
      isolateDevice: false,
      disableAccount: true,
      revokeSession: true,
    },
  };
