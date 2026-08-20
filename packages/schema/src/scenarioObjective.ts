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

export const scenarioObjectiveSchema =
  z.discriminatedUnion("kind", [
    accountStatusScenarioObjectiveSchema,
    sessionStatusScenarioObjectiveSchema,
  ]);

export type ScenarioObjectiveSpec =
  z.infer<typeof scenarioObjectiveSchema>;
