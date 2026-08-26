import type {
  AttackPlan,
} from "./attackPlan.js";

const PHISH_SENDER =
  "it-support@0ffice365-secure.com";

const PHISH_HOST =
  "0ffice365-secure.com";

const BROWSER =
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

/**
 * Credential phishing by link.
 *
 * The macro plan taught that an intrusion need not begin at a login; this one
 * teaches the domain the corpus could not express at all until now, mail. The
 * chain begins with a message, and the message is the evidence: a lookalike
 * sender domain, an urgency lure, and a link to a credential-harvesting page
 * that is not the real sign-in host. The victim clicks, their password is
 * captured, and the attacker signs in from their own address with a valid
 * credential and no malware anywhere.
 *
 * The lesson is that the earliest and cheapest place to catch this is the mail
 * itself, but only with a rule specific enough to clear the benign external
 * mail that shares its shape, which the background now generates. A rule that
 * fires on "an external email with a link" drowns; one that reads the link's
 * destination does not.
 */
export const PHISHING_LINK_PLAN: AttackPlan =
  {
    id: "phishing-link",
    name: "Credential phishing by link",
    difficulty: "standard",
    lesson:
      "This intrusion begins in mail, a domain no host-centric investigation will surface: there is no malware, no anomalous process, and the eventual login uses a valid credential. The evidence is the message, a lookalike sender domain and a link to a host that is not the real sign-in page, and the login that follows it from an unfamiliar address. Catch it at the mail, but only with a rule that reads the link rather than the mere presence of one, because ordinary external mail carries links too.",
    requires: {},

    techniques: [
      {
        id: "T1566.002",
        name: "Phishing: Spearphishing Link",
        tactic: "initial_access",
      },
      {
        id: "T1204.001",
        name: "User Execution: Malicious Link",
        tactic: "execution",
      },
      {
        id: "T1078.004",
        name: "Valid Accounts: Cloud Accounts",
        tactic: "initial_access",
      },
    ],

    steps: [
      {
        id: "phish-email",
        title:
          "A lure email arrives from a lookalike domain",
        techniqueId: "T1566.002",
        advanceBy: 3,
        significance: (cast) =>
          `${cast.subject.displayName} received a mailbox-quota warning from ${PHISH_SENDER}, with a link to ${PHISH_HOST}. It is one of many external messages delivered this morning.`,
        reasoning: () =>
          "Do not flag this on the strength of it being external and carrying a link, ordinary vendor and newsletter mail is exactly that, and a rule built on the pair fires all day. What separates this message is the destination of the link: the sender impersonates the sign-in provider, but the host is a lookalike registered to capture credentials, not the real one. Read the link's host, compare it to the genuine sign-in domain, and carry the address forward, it is what you will hunt for in the proxy logs to find everyone else who clicked.",
        build: (cast) => ({
          type: "EMAIL_RECEIVED",
          source: "mail",
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            userId: cast.subject.id,
            senderAddress: PHISH_SENDER,
            senderDisplayName:
              "Microsoft 365 Support",
            subject:
              "Action required: your mailbox will be locked in 24 hours",
            external: true,
            url: `https://${PHISH_HOST}/owa/verify?id=${cast.subjectAccount.username}`,
            sourceIp: cast.externalIp,
          },
        }),
      },
      {
        id: "link-click",
        title:
          "The victim's browser connects to the phishing host",
        techniqueId: "T1204.001",
        advanceBy: 2,
        significance: (cast) =>
          `A browser on ${cast.subjectDevice.hostname} made an outbound HTTPS connection to ${PHISH_HOST} moments after the email arrived.`,
        reasoning: () =>
          "This is the click, and it converts a delivered lure into an actioned one, the difference between a message that was blocked or ignored and a credential that is now in someone else's hands. The connection itself looks like any other web request; what makes it matter is the destination and the timing, seconds after the mail. Establish whether credentials were entered before assuming the worst, but treat the account as at risk from here, and pivot on the host to find every other click.",
        build: (cast) => ({
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            protocol: "tcp",
            sourceIp: cast.subjectIp,
            destinationIp: cast.c2Ip,
            sourcePort: 51544,
            destinationPort: 443,
            image: BROWSER,
          },
        }),
      },
      {
        id: "attacker-auth",
        title:
          "The captured credential is used from an unfamiliar address",
        techniqueId: "T1078.004",
        advanceBy: 5,
        significance: (cast) =>
          `A successful sign-in for ${cast.subjectAccount.username} from ${cast.externalIp}, an address this account has never used, minutes after the click.`,
        reasoning: () =>
          "This is the payoff, and it is a valid-accounts login: the credential is real, the multi-factor step was either absent or satisfied by the same phishing page, and nothing about the authentication is malformed. What is anomalous is the context, a new source address, and a sequence that starts at a lure the same account received minutes earlier. Correlate the sign-in back to the mail and the click; individually each is weak, together they are the intrusion. Revoke the session and reset the credential, because unlike a host compromise there is nothing on a machine to isolate.",
        build: (cast) => ({
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          subjectId: cast.subjectAccount.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            userId: cast.subject.id,
            sourceIp: cast.externalIp,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-sender",
        prompt: () =>
          "What was the sender address of the phishing email?",
        accepted: () => [
          PHISH_SENDER,
          PHISH_HOST,
        ],
        hint: "Read the mail log for the message that opened the incident.",
        surface: "siem",
        points: 25,
        evidenceStepId: "phish-email",
      },
      {
        id: "q-host",
        prompt: () =>
          "Which host did the link point to?",
        accepted: () => [
          PHISH_HOST,
          `https://${PHISH_HOST}`,
        ],
        hint: "It impersonates the sign-in provider but is not the genuine domain.",
        surface: "siem",
        points: 25,
        evidenceStepId: "phish-email",
      },
      {
        id: "q-source",
        prompt: () =>
          "From which address did the attacker sign in with the captured credential?",
        accepted: (cast) => [
          cast.externalIp,
        ],
        hint: "Look for a successful sign-in from an address the account has not used before.",
        surface: "identity",
        points: 25,
        evidenceStepId: "attacker-auth",
      },
      {
        id: "q-subject",
        prompt: () =>
          "What was the subject line of the phishing email?",
        accepted: () => [
          "Action required: your mailbox will be locked in 24 hours",
        ],
        hint: "The lure used urgency about mailbox access.",
        surface: "siem",
        points: 25,
        evidenceStepId: "phish-email",
      },
    ],

    alertTitle: (cast) =>
      `Sign-in from an unfamiliar address for ${cast.subjectAccount.username} after a phishing click`,
    alertSeverity: "high",
    alertStepIds: ["attacker-auth"],

    summary: (cast) =>
      `${cast.subject.displayName} received a credential-phishing email from ${PHISH_SENDER} impersonating Microsoft 365, with a link to the lookalike host ${PHISH_HOST}. A browser on ${cast.subjectDevice.hostname} connected to that host, and minutes later ${cast.subjectAccount.username} signed in successfully from ${cast.externalIp}, an address the account had never used. No malware ran and the credential was valid; the intrusion lived entirely in mail and identity.`,

    containment: {
      // Nothing on a host to isolate, the compromise is a stolen credential.
      isolateDevice: false,
      disableAccount: true,
      revokeSession: true,
    },
  };
