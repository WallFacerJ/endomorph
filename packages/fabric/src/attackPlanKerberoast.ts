import type {
  AttackPlan,
} from "./attackPlan.js";

const POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const RUBEUS =
  "C:\\Users\\Public\\rubeus.exe";
const MIMIKATZ =
  "C:\\Users\\Public\\m.exe";

/**
 * Active Directory credential theft: Kerberoasting to DCSync to Golden Ticket.
 *
 * One of the most common real-world chains, and one an endpoint-only or a
 * network-only view keeps missing pieces of. It runs almost entirely as valid,
 * authenticated activity: a domain user requests service tickets that anyone is
 * allowed to request, cracks them offline where no sensor can see, replicates
 * the directory the way a domain controller does, and forges a ticket that is
 * cryptographically valid. The signal is in the command lines of the tools and
 * in one structural fact: directory replication should only ever come from a
 * domain controller, never from a workstation.
 *
 * The lesson is that "valid credential" is not the same as "authorised action".
 * Every step here uses legitimate protocols; what betrays it is the tooling and
 * the source, not a failed login.
 */
export const KERBEROAST_PLAN: AttackPlan =
  {
    id: "ad-credential-theft",
    name: "Active Directory credential theft (Kerberoasting to DCSync)",
    difficulty: "advanced",
    lesson:
      "This chain lives inside valid Kerberos: service tickets any user may request, an offline crack no sensor sees, a directory replication that looks like domain-controller traffic, and a forged ticket that is cryptographically valid. A failed login will never surface it. What does is the tooling in the command lines and one structural rule: replication of the directory should only ever come from a domain controller, so a DCSync from a workstation is the near-unambiguous signal to build a detection on.",
    requires: {
      windowsWorkstation: true,
    },

    techniques: [
      {
        id: "T1558.003",
        name: "Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic: "credential_access",
      },
      {
        id: "T1550.003",
        name: "Use Alternate Authentication Material: Pass the Ticket",
        tactic: "lateral_movement",
      },
      {
        id: "T1003.006",
        name: "OS Credential Dumping: DCSync",
        tactic: "credential_access",
      },
      {
        id: "T1558.001",
        name: "Steal or Forge Kerberos Tickets: Golden Ticket",
        tactic: "persistence",
      },
    ],

    steps: [
      {
        id: "kerberoast",
        title:
          "Service tickets are requested for offline cracking",
        techniqueId: "T1558.003",
        advanceBy: 3,
        significance: (cast) =>
          `A tool on ${cast.subjectDevice.hostname} requested Kerberos service tickets for every account with a service principal name, to crack their passwords offline.`,
        reasoning: () =>
          "Requesting a service ticket is something any domain user is allowed to do, so the request itself is not the anomaly; requesting one for every service account at once is. The attacker takes the encrypted tickets away to crack the service-account passwords where no sensor can watch. Note which accounts were targeted, because the weakest password among them is the one that becomes the next foothold, and service accounts are chosen precisely because their passwords are old and rarely rotated.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "6120",
            image: POWERSHELL,
            commandLine:
              "powershell.exe -Command Invoke-Kerberoast -OutputFormat Hashcat",
            parentProcessId: "5900",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "pass-the-ticket",
        title:
          "A cracked ticket is injected to move laterally",
        techniqueId: "T1550.003",
        advanceBy: 4,
        significance: (cast) =>
          `A ticket for a cracked service account was injected into the session on ${cast.subjectDevice.hostname} and used to reach a server, with no password ever entered.`,
        reasoning: () =>
          "This is the payoff of the crack, and it is authentication without a login: the ticket is presented directly, so there is no password prompt and no failed attempt to alert on. The account is valid and the traffic is normal Kerberos. What is anomalous is the tooling that injected the ticket and the account arriving from a host it has never used. Treat any ticket injection as hostile, and pivot on the service account to see everywhere it has since been used.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "6210",
            image: RUBEUS,
            commandLine: `${RUBEUS} ptt /ticket:doIFuj...`,
            parentProcessId: "5900",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "dcsync",
        title:
          "The directory is replicated from a workstation",
        techniqueId: "T1003.006",
        advanceBy: 3,
        significance: (cast) =>
          `${cast.subjectDevice.hostname} performed a directory replication, pulling the krbtgt account hash the way a domain controller would. A workstation has no legitimate reason to do this.`,
        reasoning: () =>
          "This is the near-unambiguous signal, and the best place to build a detection. Directory replication is how domain controllers stay in sync; a workstation requesting it is impersonating a domain controller to pull password hashes, and the krbtgt hash in particular is the key to the whole domain. There is no benign version of this from a workstation, so it is high-signal and low-noise. Once krbtgt is taken, assume the entire domain is compromised and plan a krbtgt reset, twice, as part of recovery.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "6320",
            image: MIMIKATZ,
            commandLine: `${MIMIKATZ} "lsadump::dcsync /domain:corp.local /user:krbtgt"`,
            parentProcessId: "5900",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "golden-ticket",
        title:
          "A golden ticket is forged for persistence",
        techniqueId: "T1558.001",
        advanceBy: 2,
        significance: (cast) =>
          `Using the krbtgt hash, a golden ticket was forged on ${cast.subjectDevice.hostname}, granting arbitrary domain access that survives password resets of every account except krbtgt itself.`,
        reasoning: () =>
          "This is the persistence, and it is why the krbtgt hash matters so much: a golden ticket is a self-signed Kerberos ticket for any user, any group, valid until the krbtgt password is changed. Resetting the compromised user's password does nothing. This is what turns the incident from a contained compromise into a full-domain rebuild question, and it is why the krbtgt reset is the non-negotiable recovery step. Record that a golden ticket was forged, because it changes the entire scope of the response.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "6410",
            image: MIMIKATZ,
            commandLine: `${MIMIKATZ} "kerberos::golden /user:Administrator /domain:corp.local /krbtgt:HASH /ptt"`,
            parentProcessId: "5900",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-kerberoast",
        prompt: () =>
          "Which technique requested service tickets for offline cracking? Name the command.",
        accepted: () => [
          "Invoke-Kerberoast",
          "Kerberoast",
        ],
        hint: "A PowerShell command that outputs hashes in a cracker format.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "kerberoast",
      },
      {
        id: "q-dcsync",
        prompt: () =>
          "Which account's hash was replicated from the directory?",
        accepted: () => ["krbtgt"],
        hint: "The one account whose hash is the key to the whole domain.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "dcsync",
      },
      {
        id: "q-operation",
        prompt: () =>
          "What directory operation did the workstation perform that only a domain controller should?",
        accepted: () => [
          "dcsync",
          "lsadump::dcsync",
          "replication",
        ],
        hint: "How domain controllers keep their copies of the directory in sync.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "dcsync",
      },
      {
        id: "q-persistence",
        prompt: () =>
          "What kind of forged ticket was created for domain persistence?",
        accepted: () => [
          "golden",
          "golden ticket",
          "kerberos::golden",
        ],
        hint: "A self-signed ticket valid until the krbtgt password changes.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "golden-ticket",
      },
    ],

    alertTitle: () =>
      `Domain credential theft: a workstation is acting as a domain controller`,
    alertSeverity: "critical",
    alertStepIds: ["dcsync"],

    summary: (cast) =>
      `On ${cast.subjectDevice.hostname}, an attacker requested Kerberos service tickets for offline cracking (Invoke-Kerberoast), injected a cracked ticket to move laterally, replicated the directory to pull the krbtgt hash the way a domain controller would (DCSync), and forged a golden ticket for domain-wide persistence. Every step used valid Kerberos; the near-unambiguous signal was the directory replication coming from a workstation rather than a domain controller.`,

    containment: {
      isolateDevice: true,
      disableAccount: true,
      revokeSession: true,
    },
  };
