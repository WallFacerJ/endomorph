import type {
  ScenarioDefinition,
  SiemEventRecord,
} from "./simulationAdapter";

/**
 * Walkthrough step derivation.
 *
 * Kept out of the component module so React Fast Refresh keeps working and
 * so the mapping from event type to console can be tested directly.
 */

const CONSOLE_FOR_EVENT: Record<
  string,
  string
> = {
  AUTH_LOGIN_SUCCEEDED: "Identity",
  AUTH_LOGIN_FAILED: "Identity",
  SESSION_STARTED: "Identity",
  SESSION_REVOKED: "Identity",
  ACCOUNT_DISABLED: "Identity",
  ACCOUNT_ENABLED: "Identity",
  PROCESS_STARTED: "Endpoint",
  ENDPOINT_HEARTBEAT: "Endpoint",
  ALERT_CREATED: "Alerts",
  NETWORK_CONNECTION: "SIEM Search",
  FILE_ACCESSED: "SIEM Search",
};

export interface WalkthroughStep {
  readonly index: number;
  readonly eventId: string;
  readonly time: string;
  readonly significance: string;
  readonly reasoning?: string;
  readonly techniqueId?: string;
  readonly eventType: string;
  readonly console: string;
  readonly query?: string;
}

/** Builds the steps from ground truth, enriched with where to look. */
export function buildWalkthroughSteps(
  scenario: ScenarioDefinition,
  records: readonly SiemEventRecord[],
): WalkthroughStep[] {
  const byId = new Map(
    records.map((record) => [
      record.eventId,
      record,
    ]),
  );

  return (
    scenario.groundTruth?.timeline ?? []
  ).map((step, index) => {
    const record = byId.get(step.eventId);

    const eventType =
      record?.eventType ?? "UNKNOWN";

    const sourceIp =
      record?.fields["sourceIp"];

    return {
      index: index + 1,
      eventId: step.eventId,
      time:
        record?.timestamp.slice(11, 19) ??
        "",
      significance: step.significance,
      reasoning: step.reasoning,
      techniqueId: step.techniqueId,
      eventType,
      console:
        CONSOLE_FOR_EVENT[eventType] ??
        "SIEM Search",
      query:
        typeof sourceIp === "string"
          ? `sourceIp:${sourceIp}`
          : undefined,
    };
  });
}

