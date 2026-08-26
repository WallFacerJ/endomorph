import type {
  AttackPlan,
} from "./attackPlan.js";

const ROGUE_APP = "Mail Backup Pro";

const STORAGE_RESOURCE =
  "finance-reports";

/**
 * OAuth consent grant to cloud data theft.
 *
 * The cloud control plane is where a growing share of intrusions now live, and
 * none of it touches a host: an attacker persuades a user to consent to a
 * malicious OAuth application, uses the token it returns to mint a long-lived
 * credential, enumerates storage, and copies data out to an account they
 * control. Every step is a line in a provider audit log and nothing else --
 * no process, no endpoint, and after the consent, no interactive sign-in
 * either.
 *
 * The lesson is that the audit log is the only place this is visible, and that
 * the earliest signal, the consent grant, is the one that looks most like
 * ordinary administration, because users consent to legitimate applications
 * every day. Separating the rogue app from the real ones means reading what it
 * asked for and who published it, not the mere fact of a consent.
 */
export const CLOUD_CONSENT_PLAN: AttackPlan =
  {
    id: "cloud-consent-grant",
    name: "OAuth consent grant to cloud data theft",
    difficulty: "advanced",
    lesson:
      "This intrusion never touches a host or a workstation: it is entirely cloud control-plane. A user consents to a malicious OAuth application, and from there the attacker holds a token that needs no password and trips no sign-in alert. The evidence is the audit log, an app consent to an unverified publisher requesting broad mail and file scopes, a new credential minted moments later, a burst of storage enumeration, and a copy to an external account. The consent is the earliest and hardest signal, because consenting to applications is ordinary; the rogue one is separated by its publisher and its scopes, not by the act of consent.",
    requires: {},

    techniques: [
      {
        id: "T1528",
        name: "Steal Application Access Token",
        tactic: "credential_access",
      },
      {
        id: "T1098.001",
        name: "Account Manipulation: Additional Cloud Credentials",
        tactic: "persistence",
      },
      {
        id: "T1526",
        name: "Cloud Service Discovery",
        tactic: "discovery",
      },
      {
        id: "T1537",
        name: "Transfer Data to Cloud Account",
        tactic: "exfiltration",
      },
    ],

    steps: [
      {
        id: "consent-grant",
        title:
          "A user consents to an unverified OAuth application",
        techniqueId: "T1528",
        advanceBy: 4,
        significance: (cast) =>
          `${cast.subject.displayName} granted "${ROGUE_APP}" consent to read mail and files. The app is published by an unverified third party, and the grant returns a token that acts as the user without their password.`,
        reasoning: () =>
          "Do not dismiss this as routine because users consent to applications constantly, that is exactly why it is dangerous. The signal is not the consent, it is the app: an unverified publisher requesting broad, standing access to mail and files is the profile of an application designed to exfiltrate, not to do a job. From here the attacker holds a token that needs no password and raises no sign-in alert, so treat the grant itself as the compromise. Record the application id, it is what you will revoke, and what you will hunt for across every other mailbox that consented to it.",
        build: (cast) => ({
          type: "CLOUD_AUDIT",
          source: "cloud",
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            userId: cast.subject.id,
            action: "ConsentToApplication",
            service: "EntraID",
            appDisplayName: ROGUE_APP,
            resource:
              "Mail.Read, Files.Read.All",
            sourceIp: cast.subjectIp,
            outcome: "success",
          },
        }),
      },
      {
        id: "add-credential",
        title:
          "A new credential is added from the granted token",
        techniqueId: "T1098.001",
        advanceBy: 6,
        significance: (cast) =>
          `A client secret was added to "${ROGUE_APP}" from ${cast.externalIp}, giving the attacker a long-lived credential independent of the user's password or session.`,
        reasoning: () =>
          "This is persistence, and it is the step that turns a stolen token into standing access: even if the user changes their password and the session is revoked, the added credential keeps working until someone removes it. Note the source address, the consent came from the user's own address, but this operation comes from somewhere new, which is the seam between the victim's action and the attacker's. Revoking the consent is not enough; the credential has to be pulled too, or the door stays open.",
        build: (cast) => ({
          type: "CLOUD_AUDIT",
          source: "cloud",
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            action:
              "AddServicePrincipalCredential",
            service: "EntraID",
            appDisplayName: ROGUE_APP,
            sourceIp: cast.externalIp,
            outcome: "success",
          },
        }),
      },
      {
        id: "discovery",
        title:
          "Storage is enumerated through the API",
        techniqueId: "T1526",
        repeat: 3,
        advanceBy: 2,
        significance: (cast) =>
          `Repeated storage-container listings against the tenant from ${cast.externalIp}, walking the cloud estate the way a directory listing walks a filesystem.`,
        reasoning: () =>
          "Enumeration is cheap and quiet, and on its own a single listing is unremarkable administration; what marks this is the volume and the source, a rapid sweep from the same new address that added the credential. Read it as the attacker learning what is there before taking it, which means the next step is collection, and the window to contain before data leaves is now. Pivot on the source address across the audit log to see everything that credential has touched.",
        build: (cast, index) => ({
          type: "CLOUD_AUDIT",
          source: "cloud",
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            action: "ListStorageContainers",
            service: "Storage",
            resource: `tenant-storage-${index}`,
            sourceIp: cast.externalIp,
            outcome: "success",
          },
        }),
      },
      {
        id: "exfil",
        title:
          "Data is copied to an external account",
        techniqueId: "T1537",
        advanceBy: 3,
        significance: (cast) =>
          `The ${STORAGE_RESOURCE} container was copied to a storage account outside the tenant from ${cast.externalIp}. This is the business impact.`,
        reasoning: () =>
          "This is the loss, and unlike a download to a host it leaves no endpoint trace at all, the data moves cloud-to-cloud, provider to provider, and the only record is this audit line. The destination is the tell: a copy to an account outside the tenant has no legitimate business workflow behind it. Establish what the container held to scope the disclosure, and treat the external account id as an indicator, but understand that the data is already gone; containment now is about the credential and the consent, not the file.",
        build: (cast) => ({
          type: "CLOUD_AUDIT",
          source: "cloud",
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            action:
              "CopyObjectToExternalAccount",
            service: "Storage",
            resource: STORAGE_RESOURCE,
            sourceIp: cast.externalIp,
            outcome: "success",
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-app",
        prompt: () =>
          "Which application did the user consent to?",
        accepted: () => [
          ROGUE_APP,
          "Mail Backup Pro",
        ],
        hint: "Read the cloud audit log for a consent grant to an unverified publisher.",
        surface: "siem",
        points: 25,
        evidenceStepId: "consent-grant",
      },
      {
        id: "q-source",
        prompt: () =>
          "From which address were the attacker's control-plane actions performed?",
        accepted: (cast) => [
          cast.externalIp,
        ],
        hint: "The consent came from the user's own address; the credential and exfil did not.",
        surface: "siem",
        points: 25,
        evidenceStepId: "add-credential",
      },
      {
        id: "q-resource",
        prompt: () =>
          "Which storage resource was copied out of the tenant?",
        accepted: () => [
          STORAGE_RESOURCE,
        ],
        surface: "siem",
        points: 25,
        evidenceStepId: "exfil",
      },
      {
        id: "q-action",
        prompt: () =>
          "Which control-plane operation carried the data out of the tenant?",
        accepted: () => [
          "CopyObjectToExternalAccount",
        ],
        hint: "Read the cloud audit log for the storage action with an external destination.",
        surface: "siem",
        points: 25,
        evidenceStepId: "exfil",
      },
    ],

    alertTitle: () =>
      `Data copied to an external cloud account after an OAuth consent grant`,
    alertSeverity: "high",
    alertStepIds: ["exfil"],

    summary: (cast) =>
      `${cast.subject.displayName} consented to the unverified OAuth application "${ROGUE_APP}", which requested broad mail and file scopes. Using the returned token, an actor at ${cast.externalIp} added a standing credential to the application, enumerated tenant storage, and copied the ${STORAGE_RESOURCE} container to an account outside the tenant. No host was touched and no password was used after the initial consent; the entire intrusion is visible only in the cloud control-plane audit log.`,

    containment: {
      // Nothing on a host; the levers are the consent and the added credential.
      isolateDevice: false,
      disableAccount: true,
      revokeSession: true,
    },
  };
