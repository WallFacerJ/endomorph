import { z } from "zod";

import {
  scenarioObjectiveSchema,
} from "./scenarioObjective";

export const SCENARIO_FILE_VERSION = 1;

const nonEmptyStringSchema =
  z.string().min(1);

const entityIdSchema =
  nonEmptyStringSchema;

const timestampSchema =
  nonEmptyStringSchema.refine(
    (value) =>
      Number.isFinite(Date.parse(value)),
    {
      message: "Expected a valid timestamp.",
    },
  );

const optionalEntityIdSchema =
  entityIdSchema.optional();

const entityStatusSchema = z.enum([
  "active",
  "inactive",
  "disabled",
]);

const sessionStatusSchema = z.enum([
  "active",
  "ended",
  "revoked",
]);

const fileClassificationSchema = z.enum([
  "public",
  "internal",
  "confidential",
  "restricted",
]);

const applicationKindSchema = z.enum([
  "siem",
  "edr",
  "identity",
  "email",
  "hr",
  "cloud",
  "file_server",
  "custom",
]);

const alertSeveritySchema = z.enum([
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);

const authFailureReasonSchema = z.enum([
  "invalid_credentials",
  "disabled_account",
  "mfa_failed",
  "unknown_account",
  "other",
]);

const fileAccessOperationSchema = z.enum([
  "read",
  "write",
  "create",
  "delete",
  "execute",
]);

const networkProtocolSchema = z.enum([
  "tcp",
  "udp",
  "icmp",
]);

const networkPortSchema =
  z.number().int().min(0).max(65535);

export const scenarioOrganizationSchema =
  z.object({
    id: entityIdSchema,
    name: nonEmptyStringSchema,
    status: entityStatusSchema,
    departments:
      z.array(nonEmptyStringSchema),
  }).strict();

export const scenarioUserSchema =
  z.object({
    id: entityIdSchema,
    organizationId: entityIdSchema,
    displayName: nonEmptyStringSchema,
    email: nonEmptyStringSchema,
    department: nonEmptyStringSchema,
    title: nonEmptyStringSchema.optional(),
    status: entityStatusSchema,
    accountIds: z.array(entityIdSchema),
    deviceIds: z.array(entityIdSchema),
  }).strict();

export const scenarioAccountSchema =
  z.object({
    id: entityIdSchema,
    organizationId: entityIdSchema,
    userId: entityIdSchema,
    username: nonEmptyStringSchema,
    provider: nonEmptyStringSchema,
    status: entityStatusSchema,
    roles: z.array(nonEmptyStringSchema),
  }).strict();

export const scenarioDeviceSchema =
  z.object({
    id: entityIdSchema,
    organizationId: entityIdSchema,
    hostname: nonEmptyStringSchema,
    operatingSystem: nonEmptyStringSchema,
    status: entityStatusSchema,
    ownerUserId:
      optionalEntityIdSchema,
    ipAddresses:
      z.array(nonEmptyStringSchema),
  }).strict();

export const scenarioFileEntitySchema =
  z.object({
    id: entityIdSchema,
    organizationId: entityIdSchema,
    name: nonEmptyStringSchema,
    path: nonEmptyStringSchema,
    classification:
      fileClassificationSchema,
    ownerUserId:
      optionalEntityIdSchema,
    deviceId:
      optionalEntityIdSchema,
  }).strict();

export const scenarioApplicationSchema =
  z.object({
    id: entityIdSchema,
    organizationId: entityIdSchema,
    name: nonEmptyStringSchema,
    kind: applicationKindSchema,
    status: entityStatusSchema,
  }).strict();

export const scenarioSessionSchema =
  z.object({
    id: entityIdSchema,
    accountId: entityIdSchema,
    deviceId:
      optionalEntityIdSchema,
    applicationId:
      optionalEntityIdSchema,
    startedAt: timestampSchema,
    endedAt: timestampSchema.optional(),
    status: sessionStatusSchema,
  }).strict();

export const scenarioWorldSeedSchema =
  z.object({
    simulationTime: timestampSchema,
    organizations:
      z.array(scenarioOrganizationSchema)
        .default([]),
    users:
      z.array(scenarioUserSchema)
        .default([]),
    accounts:
      z.array(scenarioAccountSchema)
        .default([]),
    devices:
      z.array(scenarioDeviceSchema)
        .default([]),
    files:
      z.array(scenarioFileEntitySchema)
        .default([]),
    applications:
      z.array(scenarioApplicationSchema)
        .default([]),
    sessions:
      z.array(scenarioSessionSchema)
        .default([]),
  }).strict();

const eventBaseShape = {
  id: entityIdSchema,
  timestamp: timestampSchema,
  source: nonEmptyStringSchema,
  actorId: optionalEntityIdSchema,
  subjectId: optionalEntityIdSchema,
};

const authLoginSucceededEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("AUTH_LOGIN_SUCCEEDED"),
    payload: z.object({
      accountId: entityIdSchema,
      userId: entityIdSchema,
      deviceId:
        optionalEntityIdSchema,
      applicationId:
        optionalEntityIdSchema,
      sourceIp:
        nonEmptyStringSchema.optional(),
    }).strict(),
  }).strict();

const authLoginFailedEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("AUTH_LOGIN_FAILED"),
    payload: z.object({
      username: nonEmptyStringSchema,
      reason: authFailureReasonSchema,
      applicationId:
        optionalEntityIdSchema,
      deviceId:
        optionalEntityIdSchema,
      sourceIp:
        nonEmptyStringSchema.optional(),
    }).strict(),
  }).strict();

const accountDisabledEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("ACCOUNT_DISABLED"),
    payload: z.object({
      accountId: entityIdSchema,
      reason:
        nonEmptyStringSchema.optional(),
    }).strict(),
  }).strict();

const accountEnabledEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("ACCOUNT_ENABLED"),
    payload: z.object({
      accountId: entityIdSchema,
      reason:
        nonEmptyStringSchema.optional(),
    }).strict(),
  }).strict();

const sessionStartedEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("SESSION_STARTED"),
    payload: z.object({
      sessionId: entityIdSchema,
      accountId: entityIdSchema,
      deviceId:
        optionalEntityIdSchema,
      applicationId:
        optionalEntityIdSchema,
    }).strict(),
  }).strict();

const sessionRevokedEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("SESSION_REVOKED"),
    payload: z.object({
      sessionId: entityIdSchema,
      reason:
        nonEmptyStringSchema.optional(),
    }).strict(),
  }).strict();

const processStartedEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("PROCESS_STARTED"),
    payload: z.object({
      deviceId: entityIdSchema,
      processId: nonEmptyStringSchema,
      image: nonEmptyStringSchema,
      commandLine:
        nonEmptyStringSchema.optional(),
      parentProcessId:
        nonEmptyStringSchema.optional(),
      accountId:
        optionalEntityIdSchema,
    }).strict(),
  }).strict();

const fileAccessedEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("FILE_ACCESSED"),
    payload: z.object({
      fileId: entityIdSchema,
      operation:
        fileAccessOperationSchema,
      deviceId:
        optionalEntityIdSchema,
      accountId:
        optionalEntityIdSchema,
    }).strict(),
  }).strict();

const networkConnectionEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("NETWORK_CONNECTION"),
    payload: z.object({
      deviceId: entityIdSchema,
      protocol: networkProtocolSchema,
      sourceIp: nonEmptyStringSchema,
      destinationIp:
        nonEmptyStringSchema,
      sourcePort:
        networkPortSchema.optional(),
      destinationPort:
        networkPortSchema.optional(),
    }).strict(),
  }).strict();

const endpointHeartbeatEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("ENDPOINT_HEARTBEAT"),
    payload: z.object({
      deviceId: entityIdSchema,
      status: entityStatusSchema,
      ipAddresses:
        z.array(nonEmptyStringSchema),
    }).strict(),
  }).strict();

const alertCreatedEventSchema =
  z.object({
    ...eventBaseShape,
    type:
      z.literal("ALERT_CREATED"),
    payload: z.object({
      alertId: entityIdSchema,
      title: nonEmptyStringSchema,
      severity: alertSeveritySchema,
      applicationId:
        optionalEntityIdSchema,
      relatedEventIds:
        z.array(entityIdSchema),
      relatedEntityIds:
        z.array(entityIdSchema),
    }).strict(),
  }).strict();

export const scenarioEventSchema =
  z.discriminatedUnion("type", [
    authLoginSucceededEventSchema,
    authLoginFailedEventSchema,
    accountDisabledEventSchema,
    accountEnabledEventSchema,
    sessionStartedEventSchema,
    sessionRevokedEventSchema,
    processStartedEventSchema,
    fileAccessedEventSchema,
    networkConnectionEventSchema,
    endpointHeartbeatEventSchema,
    alertCreatedEventSchema,
  ]);

export const scenarioActionAssessmentSchema =
  z.object({
    penalty:
      z.number()
        .int()
        .min(0)
        .max(100),
    rationale: nonEmptyStringSchema,
  }).strict();

export const scenarioActionSchema =
  z.object({
    id: nonEmptyStringSchema,
    label: nonEmptyStringSchema,
    description: nonEmptyStringSchema,
    events:
      z.array(scenarioEventSchema)
        .min(1),
    assessment:
      scenarioActionAssessmentSchema
        .optional(),
  }).strict();

export const scenarioInvestigationSchema =
  z.object({
    alertId: entityIdSchema,
    userId: entityIdSchema,
    accountId: entityIdSchema,
    deviceId: entityIdSchema,
    sessionId: entityIdSchema,
    primaryActionId: nonEmptyStringSchema,
    responseActionIds:
      z.array(nonEmptyStringSchema)
        .min(1)
        .optional(),
  }).strict();

export const scenarioSpecSchema =
  z.object({
    id: nonEmptyStringSchema,
    name: nonEmptyStringSchema,
    description: nonEmptyStringSchema,
    initialWorld:
      scenarioWorldSeedSchema,
    openingEvents:
      z.array(scenarioEventSchema),
    actions:
      z.array(scenarioActionSchema),
    objectives:
      z.array(scenarioObjectiveSchema)
        .min(1),
    investigation:
      scenarioInvestigationSchema,
  }).strict();

export const scenarioFileSchema =
  z.object({
    version:
      z.literal(SCENARIO_FILE_VERSION),
    kind:
      z.literal("polymorph-scenario"),
    scenario: scenarioSpecSchema,
  }).strict();

export type ScenarioWorldSeedSpec =
  z.infer<typeof scenarioWorldSeedSchema>;

export type ScenarioEventSpec =
  z.infer<typeof scenarioEventSchema>;

export type ScenarioActionAssessmentSpec =
  z.infer<typeof scenarioActionAssessmentSchema>;

export type ScenarioActionSpec =
  z.infer<typeof scenarioActionSchema>;

export type ScenarioInvestigationSpec =
  z.infer<typeof scenarioInvestigationSchema>;

export type ScenarioSpec =
  z.infer<typeof scenarioSpecSchema>;

export type ScenarioFile =
  z.infer<typeof scenarioFileSchema>;

export function parseScenarioFile(
  input: unknown,
): ScenarioFile {
  return scenarioFileSchema.parse(input);
}

export function parseScenarioJson(
  serialized: string,
): ScenarioFile {
  let value: unknown;

  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error(
      "Scenario file is not valid JSON.",
    );
  }

  return parseScenarioFile(value);
}
