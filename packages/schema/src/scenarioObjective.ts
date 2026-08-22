import { z } from "zod";

const nonEmptyStringSchema =
  z.string().min(1);

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

const objectiveBaseShape = {
  id: nonEmptyStringSchema,
  label: nonEmptyStringSchema,
  description: nonEmptyStringSchema,
};

export const accountStatusScenarioObjectiveSchema =
  z.object({
    ...objectiveBaseShape,
    kind: z.literal("account_status"),
    accountId: nonEmptyStringSchema,
    expectedStatus: entityStatusSchema,
  }).strict();

export const sessionStatusScenarioObjectiveSchema =
  z.object({
    ...objectiveBaseShape,
    kind: z.literal("session_status"),
    sessionId: nonEmptyStringSchema,
    expectedStatus: sessionStatusSchema,
  }).strict();

/**
 * Whether the host is off the network.
 *
 * Added because containment was only expressible as an identity action. For
 * an intrusion that persists through a run key and beacons out, isolating
 * the endpoint is the response that matters and disabling the credential
 * leaves the malware running -- so an analyst doing the right thing scored
 * nothing for it.
 */
export const deviceStatusScenarioObjectiveSchema =
  z.object({
    ...objectiveBaseShape,
    kind: z.literal("device_status"),
    deviceId: nonEmptyStringSchema,
    expectedStatus: entityStatusSchema,
  }).strict();

export const scenarioObjectiveSchema =
  z.discriminatedUnion("kind", [
    accountStatusScenarioObjectiveSchema,
    sessionStatusScenarioObjectiveSchema,
    deviceStatusScenarioObjectiveSchema,
  ]);

export type ScenarioObjectiveSpec =
  z.infer<typeof scenarioObjectiveSchema>;
