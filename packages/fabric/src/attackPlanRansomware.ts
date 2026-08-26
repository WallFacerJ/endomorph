import type {
  AttackPlan,
} from "./attackPlan.js";

const SCHTASKS =
  "C:\\Windows\\System32\\schtasks.exe";
const POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const VSSADMIN =
  "C:\\Windows\\System32\\vssadmin.exe";
const PAYLOAD =
  "C:\\Users\\Public\\svchost.exe";

/**
 * Human-operated ransomware deployment.
 *
 * The end of the kill chain the other intrusions stop short of: impact. Once an
 * operator has a foothold, the last few minutes are a fast, loud sequence with a
 * recognisable shape -- establish persistence, blind the defenses, destroy the
 * backups, then encrypt. Each step is a well-known, high-fidelity signal, and
 * the destruction of recovery options is the one that most reliably separates
 * ransomware from ordinary administration: nothing legitimate deletes every
 * shadow copy on a workstation.
 *
 * The lesson is that impact is detectable *before* the encryption finishes if
 * the precursors are watched -- the shadow-copy deletion in particular is a
 * near-unambiguous last chance to contain before the files are gone.
 */
export const RANSOMWARE_PLAN: AttackPlan =
  {
    id: "ransomware-deployment",
    name: "Human-operated ransomware deployment",
    difficulty: "advanced",
    lesson:
      "This is the end of the kill chain the other intrusions stop before: impact. The final minutes are a loud, recognisable sequence -- a scheduled task for persistence, security tooling disabled, volume shadow copies destroyed, then mass encryption. The highest-fidelity signal is the shadow-copy deletion: nothing legitimate wipes every restore point on a workstation, and catching it is the last chance to contain before the files are encrypted. Watch the precursors, not the encryption, because by the time files are being encrypted it is already too late.",
    requires: {
      windowsWorkstation: true,
    },

    techniques: [
      {
        id: "T1053.005",
        name: "Scheduled Task/Job: Scheduled Task",
        tactic: "persistence",
      },
      {
        id: "T1562.001",
        name: "Impair Defenses: Disable or Modify Tools",
        tactic: "defense_evasion",
      },
      {
        id: "T1490",
        name: "Inhibit System Recovery",
        tactic: "impact",
      },
      {
        id: "T1486",
        name: "Data Encrypted for Impact",
        tactic: "impact",
      },
    ],

    steps: [
      {
        id: "scheduled-task",
        title:
          "A scheduled task is created for the payload",
        techniqueId: "T1053.005",
        advanceBy: 2,
        significance: (cast) =>
          `schtasks.exe registered a task on ${cast.subjectDevice.hostname} to run a binary from a world-writable directory as SYSTEM at logon.`,
        reasoning: () =>
          "On its own a new scheduled task is ordinary administration; what marks this one is what it runs and as whom -- a binary in C:\\Users\\Public, a directory any user can write, executed as SYSTEM. Legitimate tasks point at installed software in protected paths. Record the task name and its target: the target is the payload, and the task is how it survives a reboot even if the session is killed.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5120",
            image: SCHTASKS,
            commandLine: `schtasks.exe /create /tn "OneDriveUpdater" /tr "${PAYLOAD}" /sc onlogon /ru SYSTEM`,
            parentProcessId: "4980",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "disable-defenses",
        title:
          "Endpoint protection is disabled",
        techniqueId: "T1562.001",
        advanceBy: 1,
        significance: (cast) =>
          `Real-time protection was turned off on ${cast.subjectDevice.hostname} through a PowerShell preference change moments before the destructive stage.`,
        reasoning: () =>
          "Turning off real-time protection is not something users do, and doing it seconds before the next steps is the tell. Treat any programmatic disabling of endpoint protection as hostile until proven otherwise, and note the timing -- defenses are blinded immediately before the irreversible actions, so this is the last moment the endpoint agent could still have raised an alert on what follows.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5188",
            image: POWERSHELL,
            commandLine:
              "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
            parentProcessId: "4980",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "delete-shadows",
        title:
          "Volume shadow copies are destroyed",
        techniqueId: "T1490",
        advanceBy: 1,
        significance: (cast) =>
          `vssadmin deleted every shadow copy on ${cast.subjectDevice.hostname}, removing the ability to roll the machine back. This is the highest-fidelity signal in the chain.`,
        reasoning: () =>
          "This is the near-unambiguous one. No legitimate workflow deletes all volume shadow copies on a workstation -- backups are managed centrally, not wiped locally -- so this command is ransomware until proven otherwise, and it is the last chance to contain before encryption. If you build one detection off this plan, build it here: it is high-signal, low-noise, and it fires before the files are gone.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5240",
            image: VSSADMIN,
            commandLine:
              "vssadmin.exe delete shadows /all /quiet",
            parentProcessId: "4980",
            parentImage:
              "C:\\Windows\\System32\\cmd.exe",
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
      {
        id: "encrypt",
        title:
          "The payload encrypts the host",
        techniqueId: "T1486",
        advanceBy: 3,
        significance: (cast) =>
          `The payload masquerading as svchost.exe ran from ${PAYLOAD} and began encrypting files across ${cast.subjectDevice.hostname}, dropping a ransom note in every directory. This is the impact.`,
        reasoning: () =>
          "By the time this line appears, containment is about the rest of the estate, not this host -- its files are being encrypted now. The tell that a rule could have caught earlier is the process itself: svchost.exe is a real Windows binary, but the real one runs from System32, never from C:\\Users\\Public. Use the encrypted host to scope the incident -- which shares it had mounted, which credentials were cached -- because the operator's next move is the same sequence on every machine those reach.",
        build: (cast) => ({
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            processId: "5310",
            image: PAYLOAD,
            commandLine: `${PAYLOAD} --encrypt --note "HOW_TO_DECRYPT.txt"`,
            parentProcessId: "5120",
            parentImage: SCHTASKS,
            accountId:
              cast.subjectAccount.id,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-persistence",
        prompt: () =>
          "Which utility created the persistence task?",
        accepted: () => [
          "schtasks.exe",
          "schtasks",
        ],
        hint: "A task set to run a binary from C:\\Users\\Public as SYSTEM.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "scheduled-task",
      },
      {
        id: "q-defenses",
        prompt: () =>
          "What setting was changed to disable endpoint protection?",
        accepted: () => [
          "Set-MpPreference",
          "DisableRealtimeMonitoring",
        ],
        hint: "A PowerShell preference change to Defender.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "disable-defenses",
      },
      {
        id: "q-recovery",
        prompt: () =>
          "Which command destroyed the ability to recover the host?",
        accepted: () => [
          "vssadmin",
          "vssadmin.exe delete shadows /all /quiet",
          "vssadmin.exe",
        ],
        hint: "It removed every volume shadow copy.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "delete-shadows",
      },
      {
        id: "q-payload",
        prompt: () =>
          "What legitimate Windows binary did the encrypting payload masquerade as?",
        accepted: () => [
          "svchost.exe",
          "svchost",
        ],
        hint: "A real system binary — but it ran from C:\\Users\\Public, never where the real one lives.",
        surface: "endpoint",
        points: 25,
        evidenceStepId: "encrypt",
      },
    ],

    alertTitle: () =>
      `Ransomware deployment detected: recovery destroyed and files encrypting`,
    alertSeverity: "critical",
    alertStepIds: ["delete-shadows"],

    summary: (cast) =>
      `On ${cast.subjectDevice.hostname}, an operator registered a scheduled task pointing at a payload in C:\\Users\\Public, disabled real-time protection through a PowerShell preference change, deleted every volume shadow copy with vssadmin, and then ran the payload -- a binary masquerading as svchost.exe -- to encrypt the host and drop ransom notes. The shadow-copy deletion was the last high-fidelity chance to contain before the files were encrypted.`,

    containment: {
      isolateDevice: true,
      disableAccount: true,
      revokeSession: false,
    },
  };
