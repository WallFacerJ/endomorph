import type {
  SimulationTimestamp,
} from "@endomorph/domain";

/**
 * Business-context enrichment that the canonical domain entities do not
 * carry.
 *
 * This is deliberately a sidecar rather than new optional fields on
 * `Organization` / `Device` / `User`. The domain types are consumed by the
 * scenario schema, the compiler, and three shipped projections; widening
 * them is a change that should be made on purpose, not as a side effect of
 * building the generator. Fabric therefore emits criticality and business
 * context alongside the entities, keyed by entity id, and the Ops tools can
 * adopt it incrementally.
 */
export type AssetCriticality =
  | "low"
  | "moderate"
  | "high"
  | "severe";

export interface AssetContext {
  readonly entityId: string;

  readonly criticality: AssetCriticality;

  /** Human-readable reason, shown in tooling rather than inferred again. */
  readonly rationale: string;

  /** Department or business unit the asset belongs to. */
  readonly businessUnit: string;
}

export interface NetworkSegment {
  readonly name: string;

  readonly cidr: string;

  readonly businessUnit: string;

  readonly criticality: AssetCriticality;
}

/**
 * Input contract for enterprise generation.
 *
 * Everything that affects output is here; there are no ambient inputs, no
 * wall-clock reads, and no unseeded randomness anywhere below this type.
 */
export interface EnterpriseProfile {
  /** Root seed. The same seed and profile always yield the same enterprise. */
  readonly seed: number;

  readonly organizationName: string;

  /** Email/UPN domain, e.g. `acme.test`. */
  readonly domain: string;

  /** Approximate staff headcount; departments are filled by weight. */
  readonly headcount: number;

  /** Virtual time the generated world starts at. */
  readonly startTime: SimulationTimestamp;

  /** Share of staff issued a second, privileged account. */
  readonly privilegedAccountRate: number;

  /** Share of staff issued a second device. */
  readonly secondDeviceRate: number;

  /** Share of staff whose account is dormant or disabled. */
  readonly inactiveStaffRate: number;
}

export const DEFAULT_ENTERPRISE_PROFILE: EnterpriseProfile =
  {
    seed: 20260820,
    organizationName: "Acme Financial",
    domain: "acme.test",
    headcount: 120,
    startTime: "2026-08-20T08:00:00.000Z",
    privilegedAccountRate: 0.18,
    secondDeviceRate: 0.22,
    inactiveStaffRate: 0.06,
  };

export function resolveEnterpriseProfile(
  overrides: Partial<EnterpriseProfile> = {},
): EnterpriseProfile {
  const profile = {
    ...DEFAULT_ENTERPRISE_PROFILE,
    ...overrides,
  };

  if (
    !Number.isInteger(
      profile.headcount,
    ) ||
    profile.headcount < 1
  ) {
    throw new Error(
      "Enterprise headcount must be a positive integer.",
    );
  }

  for (const [key, value] of [
    [
      "privilegedAccountRate",
      profile.privilegedAccountRate,
    ],
    [
      "secondDeviceRate",
      profile.secondDeviceRate,
    ],
    [
      "inactiveStaffRate",
      profile.inactiveStaffRate,
    ],
  ] as const) {
    if (
      !Number.isFinite(value) ||
      value < 0 ||
      value > 1
    ) {
      throw new Error(
        `Enterprise ${key} must be between 0 and 1.`,
      );
    }
  }

  if (
    Number.isNaN(
      Date.parse(profile.startTime),
    )
  ) {
    throw new Error(
      "Enterprise startTime must be an ISO-8601 timestamp.",
    );
  }

  return profile;
}
