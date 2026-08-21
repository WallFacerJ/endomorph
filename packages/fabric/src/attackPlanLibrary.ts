import type {
  AttackPlan,
} from "./attackPlan.js";

import {
  DORMANT_ACCOUNT_PLAN,
} from "./attackPlanDormant.js";

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
        techniqueId: "T1078.002",
        advanceBy: 3,
        significance: () =>
          "Interactive session established on the compromised account.",
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
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "beacon",
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
          },
        }),
      },
      {
        id: "discovery",
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
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "collection",
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
          "What is the hostname of the compromised workstation?",
        accepted: (cast) => [
          cast.subjectDevice.hostname,
        ],
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
        techniqueId: "T1078.003",
        advanceBy: 4,
        significance: (cast) =>
          `Administrative account ${cast.privilegedAccount?.username} signed in from ${cast.subjectDevice.hostname}. The credential is valid and the address is corporate -- the anomaly is the hour, not the origin.`,
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
        techniqueId: "T1078.003",
        advanceBy: 3,
        significance: () =>
          "Elevated session opened outside the account holder's normal working window.",
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
        techniqueId: "T1087.002",
        advanceBy: 4,
        significance: () =>
          "Directory enumeration from an administrative session. Legitimate for this role, unusual at this hour.",
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
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "share-access",
        techniqueId: "T1039",
        advanceBy: 2,
        significance: (cast) =>
          `${cast.targetFile.name} read from the file share by an administrative account with no business relationship to ${cast.targetFile.classification} ${cast.subject.department} data.`,
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
        techniqueId: "T1560.001",
        advanceBy: 3,
        significance: () =>
          "Collected material compressed into a single archive, staged for removal.",
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
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "clear-logs",
        techniqueId: "T1070.001",
        advanceBy: 2,
        significance: () =>
          "Security event log cleared from the same session. Administrators rarely clear logs; this is the step that makes intent hard to argue with.",
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
        techniqueId: "T1078.002",
        advanceBy: 3,
        significance: (cast) =>
          `Privileged account ${cast.privilegedAccount?.username} authenticated from ${cast.subjectDevice.hostname}, a workstation it has no prior history with.`,
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
        techniqueId: "T1078.002",
        advanceBy: 2,
        significance: () =>
          "Session opened on the privileged account from the unfamiliar host.",
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
        techniqueId: "T1018",
        advanceBy: 3,
        significance: () =>
          "Remote system discovery across the datacenter segment. Mapping what the credential can reach.",
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
            accountId:
              cast.privilegedAccount?.id ??
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "smb-primary",
        techniqueId: "T1021.002",
        advanceBy: 2,
        significance: (cast) =>
          `SMB session to ${cast.lateralTarget.hostname} using the privileged credential.`,
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
          },
        }),
      },
      {
        id: "smb-secondary",
        techniqueId: "T1021.002",
        advanceBy: 2,
        significance: (cast) =>
          `Second SMB session, this time to ${cast.secondaryTarget.hostname}. The account is moving, not working.`,
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
          },
        }),
      },
      {
        id: "tool-transfer",
        techniqueId: "T1570",
        advanceBy: 3,
        significance: (cast) =>
          `Executable copied to ${cast.secondaryTarget.hostname} over the admin share.`,
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
          "From which workstation was that account used?",
        accepted: (cast) => [
          cast.subjectDevice.hostname,
        ],
        hint: "Compare against where this account normally authenticates.",
        surface: "identity",
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
  ];
