import type {
  AttackPlan,
} from "./attackPlan.js";

const POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

const WINWORD =
  "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

const OUTLOOK =
  "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE";

const ATTACHMENT =
  "Invoice_Remittance_Aug.docm";

/**
 * Macro execution from a phishing attachment.
 *
 * The fifth lesson, and the one the other four leave open. Every existing
 * plan opens with an identity event, a spray, an administrative sign-in, a
 * service account authenticating, a re-enabled account, so an analyst who
 * learns "start in Identity, find the anomalous authentication" is never
 * wrong here, and learns a habit that will fail them on the single most
 * common intrusion in the world.
 *
 * Nothing is wrong with the authentication in this incident because there is
 * no attacker authentication. The account is the real employee's, the device
 * is theirs, the address is their usual one, and they were already signed in
 * when it started. The compromise begins with a process.
 *
 * It is also the plan where parent lineage carries the finding rather than
 * supporting it. powershell.exe is unremarkable and runs constantly on this
 * estate, including from the task scheduler; what no legitimate workflow
 * does is launch it from a word processor.
 */
export const MACRO_EXECUTION_PLAN: AttackPlan =
  {
    id: "macro-execution",
    name: "Phishing attachment with macro execution",
    difficulty: "standard",
    lesson:
      "Not every intrusion begins at a login. Here the account is the genuine employee's, signed in from their own device at their usual hour, and no authentication in the incident is anomalous, so an investigation that starts in Identity and works outward finds nothing to explain. The chain begins with a process, and the evidence is lineage: powershell.exe is ordinary, and powershell.exe launched by a word processor is not.",
    requires: {
      windowsWorkstation: true,
      restrictedFile: true,
    },

    techniques: [
      {
        id: "T1566.001",
        name: "Phishing: Spearphishing Attachment",
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
        id: "T1547.001",
        name: "Registry Run Keys / Startup Folder",
        tactic: "persistence",
      },
      {
        id: "T1003.001",
        name: "OS Credential Dumping: LSASS Memory",
        tactic: "credential_access",
      },
      {
        id: "T1005",
        name: "Data from Local System",
        tactic: "collection",
      },
    ],

    steps: [
      {
        id: "attachment-open",
        title:
          "A macro-enabled attachment is opened",
        techniqueId: "T1566.001",
        advanceBy: 2,
        significance: (cast) =>
          `${cast.subject.displayName} opened ${ATTACHMENT} from Outlook. On its own this is one of several thousand documents opened across the estate today.`,
        reasoning: () =>
          "Resist marking this as the finding just because it turned out to be the first step; at the time it was indistinguishable from ordinary work, and a detection built on it would flag every attachment anyone opens. The one detail worth carrying forward is the extension, .docm is a macro-enabled document, which most business correspondence has no reason to be, but that is a weak signal on its own and belongs in a hunt rather than an alert. You will usually reach this event by working backwards from the execution, not by noticing it first.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "3120",
            image: WINWORD,
            commandLine: `WINWORD.EXE /n "C:\\Users\\${cast.subjectAccount.username}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\${ATTACHMENT}"`,
            parentProcessId: "2840",
            parentImage: OUTLOOK,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "macro-spawn",
        title:
          "A word processor launches PowerShell",
        techniqueId: "T1059.001",
        advanceBy: 1,
        significance: () =>
          `Encoded PowerShell launched with a hidden window, and its parent is ${ATTACHMENT}'s WINWORD.EXE. No business process on this estate starts a scripting host from a word processor.`,
        reasoning: () =>
          "This is the finding, and it is a lineage finding rather than a command-line one. Encoded and hidden PowerShell is suspicious anywhere, but on its own it still competes with administrative tooling that legitimately hides windows and passes encoded arguments; the estate runs scheduled PowerShell all day. What has no legitimate counterpart is the parent. Office applications open, render and print documents, nothing in that job requires spawning an interpreter, so the pairing of a document host with a scripting host is close to unambiguous, which is rare and worth using. Confirm the parent's own image rather than trusting the pid, then go back to what that parent opened.",
        build: (cast, _index, evasion) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "3204",
            image: POWERSHELL,
            // A command-line rule keys on the loud shape, the `-enc` flag and
            // a hidden window. The stealth variant obfuscates the flag (`-e`)
            // and drops the hidden window, so a rule pinned to `-enc` misses it
            // while the lineage rule (a word processor spawned a scripting host)
            // still fires: the parent is unchanged.
            commandLine:
              evasion === "stealth"
                ? "powershell.exe -nop -w 1 -ep bypass -e JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
                : "powershell.exe -nop -w hidden -ep bypass -enc JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
            parentProcessId: "3120",
            parentImage: WINWORD,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "beacon",
        techniqueId: "T1071.001",
        title:
          "Repeated outbound connection to one address",
        repeat: 3,
        advanceBy: 4,
        significance: (cast) =>
          `Outbound HTTPS to ${cast.c2Ip}, repeating at a regular interval after the macro ran.`,
        reasoning: () =>
          "Port 443 to an external address is the most ordinary traffic in the environment and the destination is not what makes this notable, the regularity is. Human browsing is bursty and irregular; a fixed interval means software, and software that starts talking to a new address seconds after an interpreter launched is the software that interpreter fetched. Pivot on the address across every host before you close this one: the value of a command and control address is that it identifies the other machines you did not know were involved.",
        build: (cast, index) => ({
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            protocol: "tcp",
            sourceIp: cast.subjectIp,
            destinationIp: cast.c2Ip,
            sourcePort: 49730 + index,
            destinationPort: 443,

            // The PowerShell WINWORD.EXE spawned. The lineage the step turns
            // on now survives into the network telemetry, so an analyst who
            // starts from the traffic still arrives at the word processor.
            processId: "3204",
            image: POWERSHELL,
          },
        }),
      },
      {
        id: "persistence",
        title:
          "A run key is written for the next reboot",
        techniqueId: "T1547.001",
        advanceBy: 3,
        significance: () =>
          "A registry Run key written from the same PowerShell session, so the payload survives a restart.",
        reasoning: () =>
          "Persistence is what separates an incident you can close by rebooting from one you cannot, so this step changes the response rather than the diagnosis. Note that it also changes the containment question: isolating the host stops the beacon but leaves the key in place, and the machine will start talking again the moment it is returned to the network. Whatever you decide, record the key's value, it names the payload, and the payload is what you will hunt for on every other host.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "3288",
            image:
              "C:\\Windows\\System32\\reg.exe",
            commandLine:
              'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v OneDriveSync /t REG_SZ /d "C:\\Users\\Public\\odsync.exe" /f',
            parentProcessId: "3204",
            parentImage: POWERSHELL,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "credential-access",
        title:
          "Process memory dumped for credentials",
        techniqueId: "T1003.001",
        advanceBy: 4,
        significance: () =>
          "LSASS memory dumped through rundll32 and a signed Windows library. This is an attempt to take credentials off the host.",
        reasoning: () =>
          "Read this as a scope change rather than another indicator. Everything before it concerns one machine; this step is an attempt to obtain credentials that work on others, and you must now assume that every credential cached on this host is compromised, including any administrator who has logged in here recently, which is the detail that turns a single-workstation incident into an estate-wide one. Check which accounts had sessions on this host, and treat the answer as your containment scope. Note also that the tooling is entirely signed and built in, so allow-listing by publisher would not have stopped it.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "3310",
            image:
              "C:\\Windows\\System32\\rundll32.exe",
            commandLine:
              "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Users\\Public\\ls.bin full",
            parentProcessId: "3204",
            parentImage: POWERSHELL,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "collection",
        title:
          "Restricted document read from the host",
        techniqueId: "T1005",
        advanceBy: 3,
        significance: (cast) =>
          `${cast.targetFile.name} read from ${cast.subjectDevice.hostname}. This is the business impact.`,
        reasoning: () =>
          "This is the step the business will ask about first, and the one where precision matters most. The account genuinely had access, so the question is not whether the read was permitted but whether the person made it, and by this point in the timeline the answer is that a process running under their name did, which is a different claim you must be careful to make correctly. Establish whether the file left the host before describing this as a loss; reading and exfiltration are separate events and only one of them is reportable.",
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
    ],

    questions: [
      {
        id: "q-parent",
        prompt: () =>
          "Which process launched the encoded PowerShell? Give the image name.",
        accepted: () => [
          "winword.exe",
          "winword",
          "WINWORD.EXE",
        ],
        hint: "The parent column on the endpoint answers this; the pid alone will not, because the parent started before the window.",
        surface: "endpoint",
        points: 30,
        evidenceStepId: "macro-spawn",
      },
      {
        id: "q-attachment",
        prompt: () =>
          "Which file did the user open immediately before the execution?",
        accepted: () => [
          ATTACHMENT,
          "Invoice_Remittance_Aug",
        ],
        hint: "Read the command line of the parent process.",
        surface: "endpoint",
        points: 15,
        evidenceStepId: "attachment-open",
      },
      {
        id: "q-c2",
        prompt: () =>
          "Which external address did the host beacon to?",
        accepted: (cast) => [cast.c2Ip],
        hint: "Look for a repeating outbound connection rather than a single one.",
        surface: "siem",
        points: 15,
        evidenceStepId: "beacon",
      },
      {
        id: "q-persistence",
        prompt: () =>
          "Which utility was used to establish persistence?",
        accepted: () => [
          "reg.exe",
          "reg",
        ],
        surface: "endpoint",
        points: 10,
        evidenceStepId: "persistence",
      },
      {
        id: "q-credentials",
        prompt: () =>
          "Which process was used to dump credentials from memory?",
        accepted: () => [
          "rundll32.exe",
          "rundll32",
        ],
        hint: "The library it loads matters more than the binary, which is signed and legitimate.",
        surface: "endpoint",
        points: 20,
        evidenceStepId: "credential-access",
      },
      {
        id: "q-file",
        prompt: () =>
          "Which restricted document was read?",
        accepted: (cast) => [
          cast.targetFile.name,
        ],
        surface: "siem",
        points: 10,
        evidenceStepId: "collection",
      },
    ],

    alertTitle: (cast) =>
      `Office application spawned a scripting host on ${cast.subjectDevice.hostname}`,
    alertSeverity: "high",
    alertStepIds: ["macro-spawn"],

    summary: (cast) =>
      `${cast.subject.displayName} opened ${ATTACHMENT} on ${cast.subjectDevice.hostname} while already signed in from their usual address. The document's macro launched encoded PowerShell, which beaconed to ${cast.c2Ip}, wrote a Run key for persistence, dumped LSASS memory through rundll32 and a signed Windows library, and read ${cast.targetFile.name}. No authentication in this incident is anomalous, because the attacker never authenticated, they executed inside a session the genuine user had already opened.`,

    containment: {
      isolateDevice: true,

      // LSASS was dumped, so the credentials cached on this host must be
      // treated as taken even though the user did nothing wrong.
      disableAccount: true,

      // Nothing to revoke. The attacker never opened a session; they
      // executed inside one the genuine user already had, and ending it
      // would leave the run key and the beacon exactly where they are.
      revokeSession: false,
    },
  };
