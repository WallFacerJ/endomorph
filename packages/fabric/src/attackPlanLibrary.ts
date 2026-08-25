import type {
  AttackPlan,
} from "./attackPlan.js";

import {
  DORMANT_ACCOUNT_PLAN,
} from "./attackPlanDormant.js";

import {
  MACRO_EXECUTION_PLAN,
} from "./attackPlanMacro.js";

import {
  CLOUD_ROLE_PLAN,
} from "./attackPlanCloudRole.js";

import {
  PHISHING_LINK_PLAN,
} from "./attackPlanPhishingLink.js";

/**
 * The shipped plan library.
 *
 * These are deliberately chosen to teach different lessons rather than to be
 * three flavours of the same intrusion. The first trains the obvious
 * heuristic -- an unfamiliar external address is suspicious. The second
 * breaks it: everything originates from a legitimate admin on their own
 * workstation, and the only signal is deviation from that person's own
 * baseline. The third breaks it a second way: the credential is valid and
 * the traffic is internal, but the account is being used from a host it has
 * no history with.
 *
 * The fourth is not about authentication at all: every sign-in in it is
 * unremarkable, and the only anomalous event is an identity lifecycle change
 * that happened before any of them.
 *
 * An analyst who learns "look for the foreign IP" from the first will fail
 * the other three, which is the point.
 */

const POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

export const CREDENTIAL_COMPROMISE_PLAN: AttackPlan =
  {
    id: "credential-compromise",
    name: "External credential compromise",
    difficulty: "standard",
    lesson:
      "Authentication provenance is the fastest way to separate an intrusion from noise. The account signed in from an address it had never used in five days of history, minutes after a burst of failures from the same address.",
    requires: {
      windowsWorkstation: true,
      departments: ["Finance"],
      restrictedFile: true,
    },

    techniques: [
      {
        id: "T1110.003",
        name: "Brute Force: Password Spraying",
        tactic: "credential_access",
      },
      {
        id: "T1078.002",
        name: "Valid Accounts: Domain Accounts",
        tactic: "initial_access",
      },
      {
        id: "T1059.001",
        name: "Command and Scripting Interpreter: PowerShell",
        tactic: "execution",
      },
      {
        id: "T1071.001",
        name: "Application Layer Protocol: Web Protocols",
        tactic: "command_and_control",
      },
      {
        id: "T1069.002",
        name: "Permission Groups Discovery: Domain Groups",
        tactic: "discovery",
      },
      {
        id: "T1005",
        name: "Data from Local System",
        tactic: "collection",
      },
      {
        id: "T1021.002",
        name: "Remote Services: SMB/Windows Admin Shares",
        tactic: "lateral_movement",
      },
    ],

    steps: [
      {
        id: "spray",
        title: "Password spray from an unfamiliar address",
        techniqueId: "T1110.003",
        repeat: 4,
        advanceBy: 2,
        significance: (cast) =>
          `Failed sign-in for ${cast.subjectAccount.username} from ${cast.externalIp}, an address outside every corporate subnet.`,
        reasoning: () =>
          "One failed sign-in is meaningless -- staff mistype passwords constantly, and the baseline is full of them. What matters is the shape: repeated failures against one account from one address that has never appeared in this environment before. Establish the address is unfamiliar before treating the failures as an attack, then pivot on the address rather than the account.",
        build: (cast) => ({
          type: "AUTH_LOGIN_FAILED",
          source: "identity",
          subjectId: cast.subject.id,
          payload: {
            username:
              cast.subjectAccount.username,
            reason: "invalid_credentials",
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.externalIp,
          },
        }),
      },
      {
        id: "auth-success",
        title: "One attempt succeeds",
        techniqueId: "T1078.002",
        advanceBy: 1,
        significance: (cast) =>
          `Successful sign-in for ${cast.subjectAccount.username} from ${cast.externalIp} moments after repeated failures. This is the compromise point.`,
        reasoning: () =>
          "This is the moment the incident becomes real, and the timestamp to anchor scope on: everything this account does afterwards is suspect, everything before it is probably the genuine user. A success following failures from the same unfamiliar address is the single strongest identity signal available -- far stronger than the success on its own, which happens thousands of times a day here.",
        build: (cast) => ({
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          actorId: cast.subjectAccount.id,
          subjectId: cast.subject.id,
          payload: {
            accountId:
              cast.subjectAccount.id,
            userId: cast.subject.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.externalIp,
          },
        }),
      },
      {
        id: "session",
        title: "Interactive session opens on the account",
        techniqueId: "T1078.002",
        advanceBy: 3,
        significance: () =>
          "Interactive session established on the compromised account.",
        reasoning: () =>
          "A session record on its own is unremarkable -- every sign-in produces one. Its value here is as an anchor: it gives you a session id to carry into the endpoint data, which is how you tie process activity on the host back to this specific logon rather than to the account generally. The account may well have other sessions running at the same time, belonging to the real user, and separating them is what stops you attributing the employee's ordinary work to the intruder.",
        build: (cast) => ({
          type: "SESSION_STARTED",
          source: "identity",
          actorId: cast.subjectAccount.id,
          subjectId: cast.sessionId,
          payload: {
            sessionId: cast.sessionId,
            accountId:
              cast.subjectAccount.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
          },
        }),
      },
      {
        id: "powershell",
        title: "Encoded PowerShell with inspection defeated",
        techniqueId: "T1059.001",
        advanceBy: 2,
        significance: () =>
          "Base64-encoded PowerShell launched with an execution-policy bypass and a hidden window. No business process on this host runs this way.",
        reasoning: () =>
          "PowerShell alone proves nothing; administrators and business tooling use it all day, which is why alerting on the binary produces noise rather than detections. The signal is the combination -- encoded payload, policy bypass, hidden window -- because each flag exists to defeat inspection and legitimate automation has no reason to use all three. Read the parent process next: what launched it tells you whether this followed the sign-in or came from something already resident.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "7734",
            image: POWERSHELL,
            commandLine:
              "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            parentProcessId: "4102",
            parentImage:
              "C:\\Windows\\explorer.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "beacon",
        title: "Repeated outbound connection to one address",
        techniqueId: "T1071.001",
        repeat: 2,
        advanceBy: 5,
        significance: (cast) =>
          `Outbound connection to ${cast.c2Ip} on 443 immediately after the encoded command. Beaconing to attacker infrastructure.`,
        reasoning: () =>
          "Port 443 to an external address is the most ordinary traffic in the environment, so the destination is not what makes this notable -- the timing is. It follows the encoded command within seconds, and repeats. Correlate on the host and the minute rather than on the port, and check whether any other host in the estate has talked to the same address, because that is how you find the rest of the compromise.",
        build: (cast, index) => ({
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            protocol: "tcp",
            sourceIp: cast.subjectIp,
            destinationIp: cast.c2Ip,
            sourcePort: 51422 + index,
            destinationPort: 443,

            /*
              The encoded PowerShell two steps up, by pid. This is the pivot
              the step's own reasoning asks for -- "check whether any other
              host talked to the same address" is answerable from the
              destination, but "what is beaconing" is only answerable from
              here.
            */
            processId: "7734",
            image: POWERSHELL,
          },
        }),
      },
      {
        id: "discovery",
        title: "Domain administrators enumerated",
        techniqueId: "T1069.002",
        advanceBy: 3,
        significance: () =>
          "Domain administrator enumeration. The intruder is looking for an escalation path.",
        reasoning: () =>
          "A Finance analyst account has no business enumerating Domain Admins, and that mismatch between the account's role and its behaviour is the finding -- not the command itself, which an administrator would run legitimately. This step also tells you intent: the intruder is looking for escalation, so widen scope to whatever that enumeration returned.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "7822",
            image:
              "C:\\Windows\\System32\\net.exe",
            commandLine:
              'net group "Domain Admins" /domain',
            parentProcessId: "7734",
            parentImage:
              POWERSHELL,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "collection",
        title: "Restricted document opened",
        techniqueId: "T1005",
        advanceBy: 3,
        significance: (cast) =>
          `Restricted document ${cast.targetFile.name} opened by an account with no routine history against it. This is the business impact.`,
        reasoning: () =>
          "This is the step that turns an intrusion into an incident with consequences, and the one the business will ask about first. Determine whether the account ever legitimately touched this document before -- prior access changes the story from theft to plausible routine. Access alone is not exfiltration; look for movement of the data afterwards before claiming it left.",
        build: (cast) => ({
          type: "FILE_ACCESSED",
          source: "file_server",
          actorId: cast.subjectAccount.id,
          subjectId: cast.targetFile.id,
          payload: {
            fileId: cast.targetFile.id,
            operation: "read",
            deviceId: cast.subjectDevice.id,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "lateral",
        title: "Movement to a second host",
        techniqueId: "T1021.002",
        advanceBy: 2,
        significance: (cast) =>
          `SMB connection from the compromised workstation to ${cast.lateralTarget.hostname}. Scope now extends beyond the initial host.`,
        reasoning: () =>
          "Scope has changed, and so has the containment decision: isolating the original workstation no longer ends the incident. Workstation-to-server SMB is normal here, so a single connection is weak on its own -- what makes it evidence is that it originates from a host already known compromised. Check what else that host reached in the same window before deciding containment is complete.",
        build: (cast) => ({
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            protocol: "tcp",
            sourceIp: cast.subjectIp,
            destinationIp:
              cast.lateralTarget
                .ipAddresses[0],
            sourcePort: 51533,
            destinationPort: 445,
            processId: "7734",
            image: POWERSHELL,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-source-ip",
        prompt: (cast) =>
          `From which source address did the successful sign-in for ${cast.subjectAccount.username} originate?`,
        accepted: (cast) => [
          cast.externalIp,
        ],
        hint: "Compare the account's sign-in history against the days before the incident.",
        surface: "identity",
        points: 20,
        evidenceStepId: "auth-success",
      },
      {
        id: "q-spray-count",
        prompt: () =>
          "How many failed sign-ins from that address preceded the successful one?",
        accepted: () => ["4"],
        hint: "Filter the SIEM by the source address.",
        surface: "siem",
        points: 15,
        evidenceStepId: "spray-1",
      },
      {
        id: "q-c2",
        prompt: () =>
          "Which external address did the workstation beacon to after the encoded command ran?",
        accepted: (cast) => [cast.c2Ip],
        hint: "Outbound network connections from the affected endpoint.",
        surface: "endpoint",
        points: 20,
        evidenceStepId: "beacon-1",
      },
      {
        id: "q-host",
        prompt: () =>
          "What is the IP address of the compromised workstation?",
        accepted: (cast) => [
          cast.subjectIp,
        ],
        hint: "The alert names the host. Open it to get its address.",
        surface: "endpoint",
        points: 10,
        evidenceStepId: "powershell",
      },
      {
        id: "q-file",
        prompt: () =>
          "Which restricted document did the intruder open?",
        accepted: (cast) => [
          cast.targetFile.name,
        ],
        hint: "File activity attributed to the compromised account.",
        surface: "siem",
        points: 20,
        evidenceStepId: "collection",
      },
      {
        id: "q-lateral",
        prompt: () =>
          "Which server did the intruder reach over SMB?",
        accepted: (cast) => [
          cast.lateralTarget.hostname,
        ],
        hint: "Destination port 445 from the affected endpoint.",
        surface: "siem",
        points: 15,
        evidenceStepId: "lateral",
      },
    ],

    alertTitle: (cast) =>
      `Suspicious encoded PowerShell on ${cast.subjectDevice.hostname}`,
    alertSeverity: "high",
    alertStepIds: [
      "powershell",
      "beacon-1",
    ],

    summary: (cast) =>
      `${cast.subject.displayName} (${cast.subject.department}) had their account compromised from ${cast.externalIp} after a short password spray. The intruder ran encoded PowerShell on ${cast.subjectDevice.hostname}, beaconed to ${cast.c2Ip}, enumerated domain administrators, opened the restricted document ${cast.targetFile.name}, and moved laterally to ${cast.lateralTarget.hostname} over SMB before endpoint detection fired.`,

    containment: {
      isolateDevice: true,
      disableAccount: true,
      revokeSession: true,
    },
  };

export const PRIVILEGED_INSIDER_PLAN: AttackPlan =
  {
    id: "privileged-insider",
    name: "Privileged insider data collection",
    difficulty: "advanced",
    lesson:
      "Nothing here came from outside. Every address is corporate, every credential is valid, and the account is entitled to what it touched. The signal is deviation from this person's own established pattern: an administrative account used outside its normal hours, against data its owner has no working relationship with, followed by log clearing.",
    requires: {
      windowsWorkstation: true,
      privilegedAccount: true,
      restrictedFile: true,
    },

    techniques: [
      {
        id: "T1078.003",
        name: "Valid Accounts: Local Accounts",
        tactic: "privilege_escalation",
      },
      {
        id: "T1087.002",
        name: "Account Discovery: Domain Account",
        tactic: "discovery",
      },
      {
        id: "T1039",
        name: "Data from Network Shared Drive",
        tactic: "collection",
      },
      {
        id: "T1560.001",
        name: "Archive Collected Data: Archive via Utility",
        tactic: "collection",
      },
      {
        id: "T1070.001",
        name: "Indicator Removal: Clear Windows Event Logs",
        tactic: "defense_evasion",
      },
    ],

    steps: [
      {
        id: "admin-auth",
        title: "Administrator signs in outside working hours",
        techniqueId: "T1078.003",
        advanceBy: 4,
        significance: (cast) =>
          `Administrative account ${cast.privilegedAccount?.username} signed in from ${cast.subjectDevice.hostname}. The credential is valid and the address is corporate -- the anomaly is the hour, not the origin.`,
        reasoning: (cast) =>
          `A domain administrator signing in is the least suspicious event in this environment; it happens continuously and any rule that flags it drowns. Nothing about this authentication is anomalous on its own, and that is the lesson of this incident -- the account is entitled to everything it is about to do, so entitlement cannot be your detection. Note the time and the device (${cast.subjectDevice.hostname}) and move on: the signal here is built later, out of purpose rather than permission.`,
        build: (cast) => ({
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          actorId:
            cast.privilegedAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.subject.id,
          payload: {
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
            userId: cast.subject.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.subjectIp,
          },
        }),
      },
      {
        id: "admin-session",
        title: "Elevated session opens",
        techniqueId: "T1078.003",
        advanceBy: 3,
        significance: () =>
          "Elevated session opened outside the account holder's normal working window.",
        reasoning: () =>
          "Anchor the session id here for the same reason as in any other incident -- it is what links the endpoint activity that follows to this specific logon. What you cannot do with it is establish wrongdoing, because an administrator holding an interactive session on a workstation is the expected state of the world. Resist the pull to treat routine artefacts as findings simply because they appear on an incident timeline; that is how reports end up long and unconvincing.",
        build: (cast) => ({
          type: "SESSION_STARTED",
          source: "identity",
          actorId:
            cast.privilegedAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.sessionId,
          payload: {
            sessionId: cast.sessionId,
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
          },
        }),
      },
      {
        id: "enumerate",
        title: "Directory queried for people, not systems",
        techniqueId: "T1087.002",
        advanceBy: 4,
        significance: () =>
          "Directory enumeration from an administrative session. Legitimate for this role, unusual at this hour.",
        reasoning: () =>
          "Directory enumeration by an administrator is ordinary work, and treating the command as the finding will not survive review. Look at what was selected instead: Department and Title are people-targeting properties rather than troubleshooting ones, and an account being queried for where someone sits in the organisation -- rather than for its group membership or last logon -- suggests the operator is choosing a person. Hold that loosely, because it is a hypothesis and not evidence, then see whether the next action lands on someone this query would have surfaced.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5120",
            image: POWERSHELL,
            commandLine:
              "powershell.exe Get-ADUser -Filter * -Properties Department,Title",
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
        id: "share-access",
        title: "Restricted file read across the share",
        techniqueId: "T1039",
        advanceBy: 2,
        significance: (cast) =>
          `${cast.targetFile.name} read from the file share by an administrative account with no business relationship to ${cast.targetFile.classification} ${cast.subject.department} data.`,
        reasoning: (cast) =>
          `This is where the incident becomes arguable, and it is the reasoning worth getting right: the account was permitted to read this file, so no access control was violated and no alert fires on the act itself. Authorisation to reach data is not authorisation to reach this data for this reason, and the discriminator is the relationship between the account and the material -- an administrator in ${cast.subject.department} has no routine business with ${cast.targetFile.classification} content they have never touched before. Pull the account's prior access history against this share before you write anything down, because a first-time read is a very different claim from an unusual one and you will be asked which you are making.`,
        build: (cast) => ({
          type: "FILE_ACCESSED",
          source: "file_server",
          actorId:
            cast.privilegedAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.targetFile.id,
          payload: {
            fileId: cast.targetFile.id,
            operation: "read",
            deviceId: cast.subjectDevice.id,
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "archive",
        title: "Collection compressed behind a password",
        techniqueId: "T1560.001",
        advanceBy: 3,
        significance: () =>
          "Collected material compressed into a single archive, staged for removal.",
        reasoning: () =>
          "Compression is not exfiltration and proves nothing about intent by itself; people archive files constantly. Two details raise it. The archive is assembled from material just read across a share rather than from the user's own work, and it is given a password, which serves no purpose for storage and every purpose for moving data past inspection. Treat the password as the strongest single indicator on this timeline, then establish whether the archive left the host -- staging and removal are separate events and only one of them is a breach.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5188",
            image:
              "C:\\Program Files\\7-Zip\\7z.exe",
            commandLine:
              '7z.exe a -tzip -pR3view C:\\Users\\Public\\archive.zip "\\\\FS-01\\Shared\\Finance"',
            parentProcessId: "5120",
            parentImage:
              POWERSHELL,
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "clear-logs",
        title: "Security event log cleared",
        techniqueId: "T1070.001",
        advanceBy: 2,
        significance: () =>
          "Security event log cleared from the same session. Administrators rarely clear logs; this is the step that makes intent hard to argue with.",
        reasoning: () =>
          "Everything before this could be argued as unusual-but-legitimate administration. Clearing the Security log cannot: it destroys the record of the preceding actions, it belongs to no routine maintenance an administrator can point to, and it follows the collection rather than preceding it. This is the step that turns a suspicion into an allegation, so record the exact time and confirm from a second source -- forwarded logs, the SIEM's own copy -- that the events you are relying on survived, because the local record no longer exists.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5204",
            image:
              "C:\\Windows\\System32\\wevtutil.exe",
            commandLine:
              "wevtutil.exe cl Security",
            parentProcessId: "5120",
            parentImage:
              POWERSHELL,
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-account",
        prompt: () =>
          "Which account performed the collection? Give the username.",
        accepted: (cast) => [
          cast.privilegedAccount
            ?.username ??
            cast.subjectAccount.username,
        ],
        hint: "It is not the account named on the alert's user.",
        surface: "identity",
        points: 20,
        evidenceStepId: "admin-auth",
      },
      {
        id: "q-origin",
        prompt: () =>
          "Which source address did the administrative sign-in come from?",
        accepted: (cast) => [
          cast.subjectIp,
        ],
        hint: "Check whether it is external at all before assuming it is.",
        surface: "identity",
        points: 15,
        evidenceStepId: "admin-auth",
      },
      {
        id: "q-archive",
        prompt: () =>
          "What utility was used to archive the collected data?",
        accepted: () => [
          "7z.exe",
          "7z",
          "7-Zip",
        ],
        surface: "endpoint",
        points: 15,
        evidenceStepId: "archive",
      },
      {
        id: "q-evasion",
        prompt: () =>
          "Which command was run to remove evidence?",
        accepted: () => [
          "wevtutil.exe cl Security",
          "wevtutil cl Security",
        ],
        hint: "Look at the last process in the session.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "clear-logs",
      },
      {
        id: "q-file",
        prompt: () =>
          "Which restricted document was read from the share?",
        accepted: (cast) => [
          cast.targetFile.name,
        ],
        surface: "siem",
        points: 25,
        evidenceStepId: "share-access",
      },
    ],

    alertTitle: (cast) =>
      `Security log cleared on ${cast.subjectDevice.hostname}`,
    alertSeverity: "high",
    alertStepIds: ["clear-logs"],

    summary: (cast) =>
      `${cast.subject.displayName} used their administrative account ${cast.privilegedAccount?.username} from their own workstation ${cast.subjectDevice.hostname}, outside normal hours, to enumerate the directory, read the restricted document ${cast.targetFile.name} from the file share, archive collected material with 7-Zip, and then clear the Security event log. No external infrastructure was involved at any point.`,

    containment: {
      isolateDevice: true,
      disableAccount: true,
      revokeSession: true,
    },
  };

export const SERVICE_ACCOUNT_ABUSE_PLAN: AttackPlan =
  {
    id: "service-account-abuse",
    name: "Service account used from an unfamiliar host",
    difficulty: "advanced",
    lesson:
      "The credential is valid and every connection is internal, so authentication provenance alone proves nothing. The signal is account-to-host affinity: this account has never authenticated from this workstation, and service accounts do not roam.",
    requires: {
      windowsWorkstation: true,
      privilegedAccount: true,
    },

    techniques: [
      {
        id: "T1078.002",
        name: "Valid Accounts: Domain Accounts",
        tactic: "initial_access",
      },
      {
        id: "T1018",
        name: "Remote System Discovery",
        tactic: "discovery",
      },
      {
        id: "T1021.002",
        name: "Remote Services: SMB/Windows Admin Shares",
        tactic: "lateral_movement",
      },
      {
        id: "T1570",
        name: "Lateral Tool Transfer",
        tactic: "lateral_movement",
      },
    ],

    steps: [
      {
        id: "service-auth",
        title: "Service account authenticates",
        techniqueId: "T1078.002",
        advanceBy: 3,
        significance: (cast) =>
          `Privileged account ${cast.privilegedAccount?.username} authenticated from ${cast.subjectDevice.hostname}, a workstation it has no prior history with.`,
        reasoning: (cast) =>
          `Service accounts authenticate constantly and by design, so volume and frequency tell you nothing here. What makes this account tractable is the opposite of the usual problem: its legitimate behaviour is narrow and highly predictable -- the same hosts, the same times, the same operations -- so deviation is far easier to establish than for a human account. Build that baseline from ${cast.subjectAccount.username}'s own history first, because every judgement that follows depends on knowing what normal looked like.`,
        build: (cast) => ({
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          actorId:
            cast.privilegedAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.subject.id,
          payload: {
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
            userId: cast.subject.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
            sourceIp: cast.subjectIp,
          },
        }),
      },
      {
        id: "service-session",
        title: "A service account opens an interactive session",
        techniqueId: "T1078.002",
        advanceBy: 2,
        significance: () =>
          "Session opened on the privileged account from the unfamiliar host.",
        reasoning: () =>
          "This is the finding, and it is easy to read straight past. A service account exists to run automation; an interactive session means a person is typing, and no maintenance workflow requires one -- administrators have their own accounts for that. The event is unremarkable in isolation and decisive in context, which is exactly the class of signal that volume-based detection misses. Anchor the timeline here and treat everything the account does afterwards as operator activity rather than automation.",
        build: (cast) => ({
          type: "SESSION_STARTED",
          source: "identity",
          actorId:
            cast.privilegedAccount?.id ??
            cast.subjectAccount.id,
          subjectId: cast.sessionId,
          payload: {
            sessionId: cast.sessionId,
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
            deviceId: cast.subjectDevice.id,
            applicationId:
              cast.identityApplication?.id,
          },
        }),
      },
      {
        id: "sweep",
        title: "Datacenter segment swept on SMB",
        techniqueId: "T1018",
        advanceBy: 3,
        significance: () =>
          "Remote system discovery across the datacenter segment. Mapping what the credential can reach.",
        reasoning: () =>
          "A scripted connection test is precisely the sort of thing a service account might legitimately run, so the command name is not the signal. The shape is: a full /24 swept on 445 is reconnaissance rather than a health check, because automation already knows the hosts it depends on and has no reason to discover them. Take the results as the attacker's own target list -- whatever answered is where they intend to go -- which scopes the incident faster than waiting to observe where they actually went.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "6301",
            image: POWERSHELL,
            commandLine:
              "powershell.exe Test-NetConnection -Port 445 -ComputerName (1..254 | % { \"10.90.1.$_\" })",
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
        id: "smb-primary",
        title: "First connection to an unfamiliar host",
        techniqueId: "T1021.002",
        advanceBy: 2,
        significance: (cast) =>
          `SMB session to ${cast.lateralTarget.hostname} using the privileged credential.`,
        reasoning: (cast) =>
          `SMB is the most ordinary protocol in a Windows estate and this connection is invisible in volume. What makes it notable is that it follows a sweep the account had no reason to run, and that it reaches ${cast.lateralTarget.hostname}, which is not part of this account's established baseline. One connection to one unfamiliar host is thin evidence; note it, and see whether it stays at one.`,
        build: (cast) => ({
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            protocol: "tcp",
            sourceIp: cast.subjectIp,
            destinationIp:
              cast.lateralTarget
                .ipAddresses[0],
            sourcePort: 52001,
            destinationPort: 445,

            // The sweep's own PowerShell: the movement is the same process
            // that did the discovery, which is what makes it movement rather
            // than two unrelated connections.
            processId: "6301",
            image: POWERSHELL,
          },
        }),
      },
      {
        id: "smb-secondary",
        title: "A second host, in sequence",
        techniqueId: "T1021.002",
        advanceBy: 2,
        significance: (cast) =>
          `Second SMB session, this time to ${cast.secondaryTarget.hostname}. The account is moving, not working.`,
        reasoning: () =>
          "The second host is what settles it. A service account reaching one unfamiliar system can be a misconfiguration or a changed dependency; reaching a series of them in sequence is movement, and the two readings lead to completely different responses. Stop assessing hosts individually at this point and start treating the credential itself as compromised -- the question is no longer which machines it touched, but everywhere it could still reach.",
        build: (cast) => ({
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            protocol: "tcp",
            sourceIp: cast.subjectIp,
            destinationIp:
              cast.secondaryTarget
                .ipAddresses[0],
            sourcePort: 52014,
            destinationPort: 445,
            processId: "6301",
            image: POWERSHELL,
          },
        }),
      },
      {
        id: "tool-transfer",
        title: "Executable written to an administrative share",
        techniqueId: "T1570",
        advanceBy: 3,
        significance: (cast) =>
          `Executable copied to ${cast.secondaryTarget.hostname} over the admin share.`,
        reasoning: () =>
          "A file copy is not inherently malicious, but the destination is the entire finding: ADMIN$ exists for remote administration, and writing an executable into it is the standard precursor to running that executable on the remote host. This is where the incident stops being about a credential and becomes about the estate, because a tool now sits on a machine nobody has examined. Scope that host before responding on this one -- isolating the source while the payload waits elsewhere achieves nothing.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "6390",
            image:
              "C:\\Windows\\System32\\xcopy.exe",
            commandLine: `xcopy.exe C:\\Users\\Public\\svc.exe \\\\${cast.secondaryTarget.hostname}\\ADMIN$\\ /Y`,
            parentProcessId: "6301",
            parentImage:
              POWERSHELL,
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-account",
        prompt: () =>
          "Which privileged account was used? Give the username.",
        accepted: (cast) => [
          cast.privilegedAccount
            ?.username ??
            cast.subjectAccount.username,
        ],
        surface: "identity",
        points: 20,
        evidenceStepId: "service-auth",
      },
      {
        id: "q-host",
        prompt: () =>
          "What is the IP address of the workstation the account was used from?",
        accepted: (cast) => [
          cast.subjectIp,
        ],
        hint: "The alert names the host; the address is on the host itself.",
        surface: "endpoint",
        points: 20,
        evidenceStepId: "service-auth",
      },
      {
        id: "q-second-target",
        prompt: () =>
          "Which second server did the account reach over SMB?",
        accepted: (cast) => [
          cast.secondaryTarget.hostname,
        ],
        hint: "There is more than one destination on port 445.",
        surface: "siem",
        points: 25,
        evidenceStepId: "smb-secondary",
      },
      {
        id: "q-transfer",
        prompt: () =>
          "Which utility was used to copy a file to the remote admin share?",
        accepted: () => [
          "xcopy.exe",
          "xcopy",
        ],
        surface: "endpoint",
        points: 20,
        evidenceStepId: "tool-transfer",
      },
      {
        id: "q-port",
        prompt: () =>
          "Which destination port characterises the lateral movement?",
        accepted: () => ["445"],
        surface: "siem",
        points: 15,
        evidenceStepId: "smb-primary",
      },
    ],

    alertTitle: (cast) =>
      `Privileged account activity from unrecognised host ${cast.subjectDevice.hostname}`,
    alertSeverity: "medium",
    alertStepIds: [
      "service-auth",
      "smb-primary",
    ],

    summary: (cast) =>
      `The privileged account ${cast.privilegedAccount?.username} was used from ${cast.subjectDevice.hostname}, a workstation with no prior authentication history for that credential. From there it swept the datacenter segment for SMB, opened sessions to ${cast.lateralTarget.hostname} and ${cast.secondaryTarget.hostname}, and copied an executable to the remote admin share. All traffic stayed internal and every credential used was valid.`,

    containment: {
      isolateDevice: true,
      disableAccount: true,
      revokeSession: true,
    },
  };

export const ATTACK_PLANS: readonly AttackPlan[] =
  [
    CREDENTIAL_COMPROMISE_PLAN,
    PRIVILEGED_INSIDER_PLAN,
    SERVICE_ACCOUNT_ABUSE_PLAN,
    DORMANT_ACCOUNT_PLAN,
    MACRO_EXECUTION_PLAN,
    CLOUD_ROLE_PLAN,
    PHISHING_LINK_PLAN,
  ];
