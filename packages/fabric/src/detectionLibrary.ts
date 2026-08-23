import type {
  DetectionRule,
} from "./detection.js";

/**
 * A starter ruleset, written against the corpus schema.
 *
 * These exist to make the evaluator demonstrable, not to be a good SOC
 * ruleset. Two of them are deliberately imperfect: `naive-powershell` fires
 * on every PowerShell launch, which is how a rule looks before anyone has
 * measured it, and `external-auth-success` encodes exactly the heuristic
 * that the insider and service-account plans defeat. Running the ruleset
 * across every plan shows both failures as numbers rather than opinions.
 *
 * The identity-lifecycle rules at the end were added after the dormant
 * account plan scored 0/4 against this set. That gap was a measurement, and
 * closing it was verifiable -- which is the loop the whole corpus exists to
 * support.
 */

export const PASSWORD_SPRAY_RULE: DetectionRule =
  {
    id: "auth-spray",
    name: "Repeated authentication failures from one source",
    technique: "T1110.003",
    severity: "medium",
    selections: [
      {
        "event.type": "AUTH_LOGIN_FAILED",
      },
    ],
    threshold: {
      groupBy: ["source.ip"],
      count: 4,
      withinMinutes: 15,
    },
  };

export const ENCODED_POWERSHELL_RULE: DetectionRule =
  {
    id: "encoded-powershell",
    name: "PowerShell with encoded command and hidden window",
    technique: "T1059.001",
    severity: "high",
    selections: [
      {
        "process.executable": {
          contains: "powershell.exe",
        },
      },
      {
        // A character class rather than \b: escaping a backslash through
        // source, JSON, and RegExp is exactly how a rule ends up matching a
        // backspace character and silently never firing.
        "process.command_line": {
          regex: "-e(nc|ncodedcommand)[ =]",
        },
      },
    ],
  };

export const NAIVE_POWERSHELL_RULE: DetectionRule =
  {
    id: "naive-powershell",
    name: "Any PowerShell execution",
    technique: "T1059.001",
    severity: "low",
    selections: [
      {
        "process.executable": {
          contains: "powershell.exe",
        },
      },
    ],
  };

export const EXTERNAL_AUTH_SUCCESS_RULE: DetectionRule =
  {
    id: "external-auth-success",
    name: "Successful sign-in from a non-corporate address",
    technique: "T1078.002",
    severity: "high",
    selections: [
      {
        "event.type":
          "AUTH_LOGIN_SUCCEEDED",
      },
    ],
    exclusions: [
      {
        "source.ip": {
          startsWith: "10.",
        },
      },
    ],
  };

export const LOG_CLEARING_RULE: DetectionRule =
  {
    id: "log-clearing",
    name: "Windows event log cleared",
    technique: "T1070.001",
    severity: "high",
    selections: [
      {
        "process.command_line": {
          contains: "wevtutil",
        },
      },
      {
        "process.command_line": {
          contains: " cl ",
        },
      },
    ],
  };

export const ARCHIVE_STAGING_RULE: DetectionRule =
  {
    id: "archive-staging",
    name: "Archive utility run against a network share",
    technique: "T1560.001",
    severity: "medium",
    selections: [
      {
        "process.executable": {
          contains: "7z.exe",
        },
      },
      {
        "process.command_line": {
          contains: "\\\\",
        },
      },
    ],
  };

export const ADMIN_SHARE_TRANSFER_RULE: DetectionRule =
  {
    id: "admin-share-transfer",
    name: "File copied to a remote admin share",
    technique: "T1570",
    severity: "high",
    selections: [
      {
        "process.command_line": {
          contains: "ADMIN$",
        },
      },
    ],
  };

export const SMB_LATERAL_RULE: DetectionRule =
  {
    id: "smb-lateral",
    name: "Workstation opening SMB sessions to servers",
    technique: "T1021.002",
    severity: "medium",
    selections: [
      {
        "event.type":
          "NETWORK_CONNECTION",
      },
      { "destination.port": 445 },
      {
        "destination.ip": {
          startsWith: "10.90.",
        },
      },
    ],
    threshold: {
      groupBy: ["host.name"],
      count: 2,
      withinMinutes: 30,
    },
  };

export const DOMAIN_GROUP_DISCOVERY_RULE: DetectionRule =
  {
    id: "domain-group-discovery",
    name: "Domain administrator group enumeration",
    technique: "T1069.002",
    severity: "medium",
    selections: [
      {
        "process.command_line": {
          contains: "Domain Admins",
        },
      },
    ],
  };

export const ACCOUNT_REENABLED_RULE: DetectionRule =
  {
    id: "account-reenabled",
    name: "Disabled account re-enabled",
    technique: "T1098",
    severity: "high",
    selections: [
      {
        "event.type": "ACCOUNT_ENABLED",
      },
    ],
  };

export const DISABLED_ENUMERATION_RULE: DetectionRule =
  {
    id: "disabled-account-enumeration",
    name: "Directory enumeration filtered to disabled accounts",
    technique: "T1087.002",
    severity: "medium",
    selections: [
      {
        "process.command_line": {
          contains: "Get-ADUser",
        },
      },
      {
        "process.command_line": {
          contains: "Enabled -eq",
        },
      },
    ],
  };

export const OFFICE_SPAWNS_SCRIPT_RULE: DetectionRule =
  {
    id: "office-spawns-script",
    name: "Office application spawned a scripting host",
    technique: "T1059.001",
    severity: "high",
    selections: [
      {
        "process.parent.executable": {
          anyOf: [
            { contains: "WINWORD.EXE" },
            { contains: "EXCEL.EXE" },
            {
              contains: "POWERPNT.EXE",
            },
            { contains: "OUTLOOK.EXE" },
          ],
        },
      },
      {
        "process.executable": {
          anyOf: [
            {
              contains: "powershell.exe",
            },
            { contains: "cmd.exe" },
            { contains: "wscript.exe" },
            { contains: "cscript.exe" },
            { contains: "mshta.exe" },
          ],
        },
      },
    ],
  };

export const RUN_KEY_PERSISTENCE_RULE: DetectionRule =
  {
    id: "run-key-persistence",
    name: "Registry run key written from a command line",
    technique: "T1547.001",
    severity: "high",
    selections: [
      {
        "process.command_line": {
          contains:
            "CurrentVersion\\Run",
        },
      },
      {
        "process.command_line": {
          contains: " add ",
        },
      },
    ],
  };

export const LSASS_DUMP_RULE: DetectionRule =
  {
    id: "lsass-memory-dump",
    name: "Process memory dumped through a signed library",
    technique: "T1003.001",
    severity: "critical",
    selections: [
      {
        "process.command_line": {
          contains: "comsvcs.dll",
        },
      },
      {
        "process.command_line": {
          contains: "MiniDump",
        },
      },
    ],
  };

/**
 * External addresses the organisation routinely talks to.
 *
 * A detection allow-list, maintained by hand, exactly as one is in practice
 * -- and deliberately one entry behind the environment it describes. The
 * estate routinely reaches a service that nobody added here, so the refined
 * rule below still carries residual noise from it.
 *
 * That gap is the point rather than an oversight. Completing the list would
 * take the rule to perfect precision against this corpus and teach something
 * false, because an allow-list is never finished: it is a snapshot of what
 * someone knew on the day they last reviewed it, and the environment keeps
 * moving. What the pair of rules below measures is how much of the problem
 * subtracting known-good actually solves, which is a great deal and not all
 * of it.
 */
const KNOWN_EXTERNAL_DESTINATIONS: readonly string[] =
  [
    "52.96.104.11",
    "142.250.187.14",
    "13.107.42.14",
    "104.18.32.47",
    "151.101.65.69",
    "34.117.59.81",
  ];

/**
 * The naive version, kept deliberately.
 *
 * Repetition alone is not a discriminator: every laptop in the estate holds
 * a polling connection to mail or chat, which has exactly this shape. The
 * rule finds the beacon and drowns it, which is the honest outcome and the
 * reason the refined rule below exists.
 */
export const NAIVE_BEACON_RULE: DetectionRule =
  {
    id: "naive-beacon",
    name: "Repeated outbound connections to one external address",
    technique: "T1071.001",
    severity: "medium",
    selections: [
      {
        "event.type":
          "NETWORK_CONNECTION",
      },
      { "destination.port": 443 },
    ],

    // Everything corporate is RFC1918 here, so excluding it is what makes
    // "external" expressible without an intelligence feed.
    exclusions: [
      {
        "destination.ip": {
          startsWith: "10.",
        },
      },
    ],

    // The destination is not the signal -- 443 outbound is the most ordinary
    // traffic in the estate. Repetition to the *same* address from the same
    // host is, because human browsing is bursty and irregular while software
    // is not.
    threshold: {
      groupBy: [
        "host.name",
        "destination.ip",
      ],
      count: 3,
      withinMinutes: 30,
    },
  };

/**
 * The refined version: repetition, minus the destinations the organisation
 * knows it talks to.
 *
 * This is what a detection engineer actually does with the naive rule above
 * -- not make the pattern cleverer, but subtract the known-good. It is worth
 * seeing the cost as well as the benefit: the allow-list is a maintenance
 * burden, it is only as good as the day it was last reviewed, and an
 * attacker who beacons through a service on it is invisible to this rule.
 */
export const UNKNOWN_DESTINATION_BEACON_RULE: DetectionRule =
  {
    id: "beacon-unknown-destination",
    name: "Repeated outbound connections to an address outside the known set",
    technique: "T1071.001",
    severity: "high",
    selections: [
      {
        "event.type":
          "NETWORK_CONNECTION",
      },
      { "destination.port": 443 },
    ],

    exclusions: [
      {
        "destination.ip": {
          startsWith: "10.",
        },
      },
      {
        "destination.ip":
          KNOWN_EXTERNAL_DESTINATIONS,
      },
    ],

    threshold: {
      groupBy: [
        "host.name",
        "destination.ip",
      ],
      count: 3,
      withinMinutes: 30,
    },
  };

/**
 * A privileged role appearing on an account.
 *
 * Precise because the event is precise: directories do not grant
 * administrative roles by accident, and the grant is a single record with no
 * volume behind it -- which is exactly why threshold detection never sees
 * it.
 */
export const PRIVILEGED_ROLE_GRANT_RULE: DetectionRule =
  {
    id: "privileged-role-grant",
    name: "Administrative role granted to an account",
    technique: "T1098.003",
    severity: "critical",
    selections: [
      {
        "event.type": "ROLE_GRANTED",
      },
      {
        "iam.role": {
          anyOf: [
            { contains: "administrator" },
            { contains: "admin" },
            { contains: "owner" },
          ],
        },
      },
    ],
  };

/**
 * A run of denied second factors against one account.
 *
 * The naive reading of failed sign-ins is that someone is guessing a
 * password. A denied multi-factor prompt says the opposite: the password was
 * already right and only the approval was missing. Keyed on the failure
 * reason for that reason, rather than on failure volume.
 */
export const MFA_DENIAL_BURST_RULE: DetectionRule =
  {
    id: "mfa-denial-burst",
    name: "Repeated multi-factor denials for one account",
    technique: "T1621",
    severity: "high",
    selections: [
      {
        "event.type":
          "AUTH_LOGIN_FAILED",
      },
      { "event.reason": "mfa_failed" },
    ],
    threshold: {
      groupBy: ["account.name"],
      count: 3,
      withinMinutes: 20,
    },
  };

export const DETECTION_RULES: readonly DetectionRule[] =
  [
    PASSWORD_SPRAY_RULE,
    ENCODED_POWERSHELL_RULE,
    NAIVE_POWERSHELL_RULE,
    EXTERNAL_AUTH_SUCCESS_RULE,
    LOG_CLEARING_RULE,
    ARCHIVE_STAGING_RULE,
    ADMIN_SHARE_TRANSFER_RULE,
    SMB_LATERAL_RULE,
    DOMAIN_GROUP_DISCOVERY_RULE,
    ACCOUNT_REENABLED_RULE,
    DISABLED_ENUMERATION_RULE,
    OFFICE_SPAWNS_SCRIPT_RULE,
    RUN_KEY_PERSISTENCE_RULE,
    LSASS_DUMP_RULE,
    NAIVE_BEACON_RULE,
    UNKNOWN_DESTINATION_BEACON_RULE,
    PRIVILEGED_ROLE_GRANT_RULE,
    MFA_DENIAL_BURST_RULE,
  ];
