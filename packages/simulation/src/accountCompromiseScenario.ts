import {
  createWorldState,
} from "./worldState";

import type {
  ScenarioDefinition,
} from "./scenario";

export const accountCompromiseScenarioIds = {
  organizationId: "org-acme",
  userId: "user-sarah-martinez",
  accountId: "account-smartinez",
  deviceId: "device-fin-lt-04",
  identityApplicationId: "app-identity",
  edrApplicationId: "app-edr",
  siemApplicationId: "app-siem",
  sessionId: "session-smartinez-compromised",
  loginEventId: "event-compromise-login",
  processEventId: "event-compromise-powershell",
  networkEventId: "event-compromise-network",
  alertEventId: "event-compromise-alert",
  alertId: "alert-compromise-powershell",
  containmentActionId: "contain_incident",
} as const;

const ids = accountCompromiseScenarioIds;

const initialWorld = createWorldState({
  simulationTime:
    "2026-08-20T15:00:00Z",
  organizations: [
    {
      id: ids.organizationId,
      name: "Acme Financial",
      status: "active",
      departments: [
        "Finance",
        "Human Resources",
        "Information Technology",
        "Security",
      ],
    },
  ],
  users: [
    {
      id: ids.userId,
      organizationId:
        ids.organizationId,
      displayName: "Sarah Martinez",
      email:
        "sarah.martinez@acme.test",
      department: "Finance",
      title: "Senior Financial Analyst",
      status: "active",
      accountIds: [ids.accountId],
      deviceIds: [ids.deviceId],
    },
  ],
  accounts: [
    {
      id: ids.accountId,
      organizationId:
        ids.organizationId,
      userId: ids.userId,
      username: "smartinez",
      provider: "Acme Identity",
      status: "active",
      roles: ["finance-user"],
    },
  ],
  devices: [
    {
      id: ids.deviceId,
      organizationId:
        ids.organizationId,
      hostname: "FIN-LT-04",
      operatingSystem: "Windows 11",
      status: "active",
      ownerUserId: ids.userId,
      ipAddresses: ["10.20.30.44"],
    },
  ],
  applications: [
    {
      id: ids.identityApplicationId,
      organizationId:
        ids.organizationId,
      name: "Acme Identity",
      kind: "identity",
      status: "active",
    },
    {
      id: ids.edrApplicationId,
      organizationId:
        ids.organizationId,
      name: "Acme Endpoint Defense",
      kind: "edr",
      status: "active",
    },
    {
      id: ids.siemApplicationId,
      organizationId:
        ids.organizationId,
      name: "Acme Security Analytics",
      kind: "siem",
      status: "active",
    },
  ],
});

export const accountCompromiseScenario:
  ScenarioDefinition = {
    id: "scenario-account-compromise-001",
    name: "Suspicious PowerShell after account compromise",
    description:
      "Investigate a suspicious login followed by encoded PowerShell activity and a correlated endpoint alert.",
    initialWorld,
    openingEvents: [
      {
        id: "event-endpoint-heartbeat",
        type: "ENDPOINT_HEARTBEAT",
        timestamp:
          "2026-08-20T15:00:00Z",
        source: "edr",
        subjectId: ids.deviceId,
        payload: {
          deviceId: ids.deviceId,
          status: "active",
          ipAddresses: ["10.20.30.44"],
        },
      },
      {
        id: ids.loginEventId,
        type: "AUTH_LOGIN_SUCCEEDED",
        timestamp:
          "2026-08-20T15:01:00Z",
        source: "identity",
        actorId: ids.accountId,
        subjectId: ids.userId,
        payload: {
          accountId: ids.accountId,
          userId: ids.userId,
          deviceId: ids.deviceId,
          applicationId:
            ids.identityApplicationId,
          sourceIp: "185.220.101.42",
        },
      },
      {
        id: "event-compromise-session",
        type: "SESSION_STARTED",
        timestamp:
          "2026-08-20T15:01:01Z",
        source: "identity",
        actorId: ids.accountId,
        subjectId: ids.userId,
        payload: {
          sessionId: ids.sessionId,
          accountId: ids.accountId,
          deviceId: ids.deviceId,
          applicationId:
            ids.identityApplicationId,
        },
      },
      {
        id: ids.processEventId,
        type: "PROCESS_STARTED",
        timestamp:
          "2026-08-20T15:03:15Z",
        source: "edr",
        actorId: ids.accountId,
        subjectId: ids.deviceId,
        payload: {
          deviceId: ids.deviceId,
          processId: "8420",
          image:
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          commandLine:
            "powershell.exe -NoProfile -EncodedCommand <synthetic-encoded-command>",
          parentProcessId: "6172",
          accountId: ids.accountId,
        },
      },
      {
        id: ids.networkEventId,
        type: "NETWORK_CONNECTION",
        timestamp:
          "2026-08-20T15:03:19Z",
        source: "edr",
        actorId: ids.accountId,
        subjectId: ids.deviceId,
        payload: {
          deviceId: ids.deviceId,
          protocol: "tcp",
          sourceIp: "10.20.30.44",
          destinationIp: "203.0.113.77",
          sourcePort: 49722,
          destinationPort: 443,
        },
      },
      {
        id: ids.alertEventId,
        type: "ALERT_CREATED",
        timestamp:
          "2026-08-20T15:03:25Z",
        source: "edr",
        subjectId: ids.deviceId,
        payload: {
          alertId: ids.alertId,
          title:
            "Suspicious encoded PowerShell after unusual login",
          severity: "high",
          applicationId:
            ids.edrApplicationId,
          relatedEventIds: [
            ids.loginEventId,
            ids.processEventId,
            ids.networkEventId,
          ],
          relatedEntityIds: [
            ids.userId,
            ids.accountId,
            ids.deviceId,
          ],
        },
      },
    ],
    actions: [
      {
        id: ids.containmentActionId,
        label: "Contain incident",
        description:
          "Revoke the active session and disable the compromised account.",
        events: [
          {
            id: "event-containment-session-revoked",
            type: "SESSION_REVOKED",
            timestamp:
              "2026-08-20T15:05:00Z",
            source: "identity",
            subjectId: ids.userId,
            payload: {
              sessionId: ids.sessionId,
              reason:
                "Analyst containment after correlated endpoint alert.",
            },
          },
          {
            id: "event-containment-account-disabled",
            type: "ACCOUNT_DISABLED",
            timestamp:
              "2026-08-20T15:05:01Z",
            source: "identity",
            subjectId: ids.userId,
            payload: {
              accountId: ids.accountId,
              reason:
                "Analyst containment after correlated endpoint alert.",
            },
          },
        ],
      },
    ],
  };
