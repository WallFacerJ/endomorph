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
    autoruns:
      z.array(
        z.object({
          name: nonEmptyStringSchema,
          location: nonEmptyStringSchema,
          target: nonEmptyStringSchema,
        }).strict(),
      ).optional(),
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

const roleGrantedEventSchema =
  z.object({
    ...eventBaseShape,
    type: z.literal("ROLE_GRANTED"),
    payload: z.object({
      accountId: entityIdSchema,
      role: nonEmptyStringSchema,
      applicationId:
        optionalEntityIdSchema,
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
      parentImage:
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

      /*
        The process responsible for the connection.

        Optional in the schema so hand-authored v1 scenarios stay valid, but
        the generator attributes every connection it emits -- benign and
        malicious alike. An optional field that only the intrusion populates
        is not a field, it is a label, and `processId exists` would be a
        perfect ground-truth filter.
      */
      processId:
        nonEmptyStringSchema.optional(),
      image:
        nonEmptyStringSchema.optional(),
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
    roleGrantedEventSchema,
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

export const scenarioGroundTruthEventSchema =
  z.object({
    eventId: entityIdSchema,
    /** Short human title, e.g. "Encoded PowerShell with inspection defeated". */
    title:
      nonEmptyStringSchema.optional(),
    significance: nonEmptyStringSchema,
    /** MITRE ATT&CK technique this step maps to, e.g. T1110.003. */
    techniqueId:
      nonEmptyStringSchema.optional(),
    /** What an analyst should conclude, and what to check next. */
    reasoning:
      nonEmptyStringSchema.optional(),
  }).strict();

/**
 * ATT&CK tactics, in kill-chain order.
 *
 * Adversary behaviour that is not mapped to a framework is just a story.
 * Mapping makes coverage, gaps, and progression measurable, which is what
 * every serious blue-team platform is assessed on.
 */
export const attackTacticSchema = z.enum([
  "reconnaissance",
  "resource_development",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
]);

export const scenarioTechniqueSchema =
  z.object({
    id: nonEmptyStringSchema,
    name: nonEmptyStringSchema,
    tactic: attackTacticSchema,
    /** Opening events that demonstrate the technique. */
    eventIds:
      z.array(entityIdSchema).min(1),
  }).strict();

/**
 * A question the analyst must answer from evidence.
 *
 * This is what separates an investigation from a click-through: the analyst
 * has to produce a specific value found in the telemetry, not recognise the
 * right card. Answers are graded against normalized text so the check stays
 * deterministic.
 */
export const scenarioQuestionSchema =
  z.object({
    id: nonEmptyStringSchema,
    prompt: nonEmptyStringSchema,
    /** Accepted answers, compared case-insensitively after trimming. */
    accepted:
      z.array(nonEmptyStringSchema).min(1),
    hint: nonEmptyStringSchema.optional(),
    /** Which console the answer is discoverable from. */
    surface: z.enum([
      "siem",
      "endpoint",
      "identity",
      "case",
    ]),
    points: z
      .number()
      .int()
      .min(1)
      .max(100),
    /** Event the answer can be read from, for after-action review. */
    evidenceEventId:
      entityIdSchema.optional(),
  }).strict();

export const scenarioGroundTruthSchema =
  z.object({
    summary: nonEmptyStringSchema,
    timeline:
      z.array(scenarioGroundTruthEventSchema)
        .min(1),
    techniques:
      z.array(scenarioTechniqueSchema)
        .optional(),
    /** Severity band, used for triage realism and reporting. */
    severity:
      alertSeveritySchema.optional(),
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

export const assetCriticalitySchema =
  z.enum([
    "low",
    "moderate",
    "high",
    "severe",
  ]);

/**
 * Business context for one entity, keyed by its id.
 *
 * The generator has always known which hosts and accounts matter -- a
 * Finance executive's laptop is not a print-room workstation -- and emitted
 * it. Until now it had nowhere to live in the file the runtime loads, so the
 * consoles triaged every asset as if it were identical. This carries the
 * judgement to them: criticality for sorting, the rationale so the label is
 * explainable rather than a bare tier, and the business unit so a host reads
 * as belonging to a part of the company.
 */
export const scenarioAssetSchema =
  z.object({
    entityId: entityIdSchema,
    criticality: assetCriticalitySchema,
    rationale: nonEmptyStringSchema,
    businessUnit: nonEmptyStringSchema,
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
    groundTruth:
      scenarioGroundTruthSchema.optional(),
    questions:
      z.array(scenarioQuestionSchema)
        .optional(),
    assets:
      z.array(scenarioAssetSchema)
        .optional(),
  }).strict();

/**
 * How a scenario file was produced.
 *
 * Optional, and present only on generated files: the hand-authored v1
 * scenarios were written, not seeded, and claiming a seed for them would be
 * a lie a reviewer might act on. When present it is the record of record for
 * reproducibility -- the same generator and seed yield byte-identical
 * telemetry, which is the whole basis on which two analysts' scores are
 * comparable. It lives on the file wrapper rather than inside the scenario
 * because it describes the artifact's origin, not the incident.
 */
export const scenarioProvenanceSchema =
  z.object({
    generator: nonEmptyStringSchema,
    seed: z.number().int(),
    planId: nonEmptyStringSchema.optional(),
  }).strict();

export const scenarioFileSchema =
  z.object({
    version:
      z.literal(SCENARIO_FILE_VERSION),
    kind:
      z.literal("endomorph-scenario"),
    scenario: scenarioSpecSchema,
    provenance:
      scenarioProvenanceSchema.optional(),
  }).strict();

export type ScenarioWorldSeedSpec =
  z.infer<typeof scenarioWorldSeedSchema>;

export type ScenarioEventSpec =
  z.infer<typeof scenarioEventSchema>;

export type ScenarioActionAssessmentSpec =
  z.infer<typeof scenarioActionAssessmentSchema>;

export type ScenarioActionSpec =
  z.infer<typeof scenarioActionSchema>;

export type AttackTactic =
  z.infer<typeof attackTacticSchema>;

export type ScenarioTechniqueSpec =
  z.infer<typeof scenarioTechniqueSchema>;

export type ScenarioQuestionSpec =
  z.infer<typeof scenarioQuestionSchema>;

export type ScenarioGroundTruthSpec =
  z.infer<typeof scenarioGroundTruthSchema>;

export type ScenarioProvenanceSpec =
  z.infer<typeof scenarioProvenanceSchema>;

export type AssetCriticalitySpec =
  z.infer<typeof assetCriticalitySchema>;

export type ScenarioAssetSpec =
  z.infer<typeof scenarioAssetSchema>;

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
