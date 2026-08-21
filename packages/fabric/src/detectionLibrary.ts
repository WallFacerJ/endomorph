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
 * across all three plans shows both failures as numbers rather than
 * opinions.
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
  ];
