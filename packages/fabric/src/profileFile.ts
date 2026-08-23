import {
  z,
} from "zod";

import {
  DEFAULT_ENTERPRISE_PROFILE,
} from "./enterpriseProfile.js";

import type {
  EnterpriseProfile,
} from "./enterpriseProfile.js";

/**
 * A client environment profile, loaded from a file.
 *
 * This is what turns a demo into an engagement: a generated estate that
 * carries the client's department names, host codes, subnet layout and
 * naming convention, so an analyst trains against something shaped like the
 * network they work in. An estate called Acme Financial teaches the same
 * analysis and feels like a toy.
 *
 * Validated rather than trusted, because it arrives as a file somebody
 * hand-wrote. That is the project's rule for anything crossing a trust
 * boundary, and it matters more here than usual: a silently ignored typo
 * would produce an estate that looks nearly right, and "nearly right" is the
 * hardest kind of wrong to notice in generated data.
 *
 * Every field is optional. A profile that sets only a domain and a
 * department list is a legitimate profile, and the rest comes from the
 * defaults.
 */

const departmentSchema = z
  .object({
    name: z.string().min(1),
    weight: z.number().positive(),

    /** Third octet of the department subnet. */
    subnetOctet: z
      .number()
      .int()
      .min(0)
      .max(255),

    hostCode: z.string().min(1),
    titles: z
      .array(z.string().min(1))
      .min(1),
    baseRoles: z.array(z.string().min(1)),
    criticality: z.enum([
      "low",
      "moderate",
      "high",
      "severe",
    ]),
  })
  .strict();

export const enterpriseProfileFileSchema = z
  .object({
    seed: z.number().int().optional(),
    organizationName: z
      .string()
      .min(1)
      .optional(),
    domain: z.string().min(1).optional(),
    headcount: z
      .number()
      .int()
      .positive()
      .optional(),
    startTime: z
      .string()
      .min(1)
      .optional(),

    privilegedAccountRate: z
      .number()
      .min(0)
      .max(1)
      .optional(),
    secondDeviceRate: z
      .number()
      .min(0)
      .max(1)
      .optional(),
    inactiveStaffRate: z
      .number()
      .min(0)
      .max(1)
      .optional(),

    departments: z
      .array(departmentSchema)
      .min(1)
      .optional(),

    workstationSubnetPrefix: z
      .string()
      .regex(
        /^\d{1,3}(\.\d{1,3})?$/,
        "Expected one or two octets, e.g. \"10\" or \"172.16\".",
      )
      .optional(),

    hostnamePattern: z
      .string()
      .min(1)
      .refine(
        (pattern) =>
          pattern.includes("{n}"),
        {
          message:
            'Hostname pattern must contain "{n}", or every host in a department would be named the same thing.',
        },
      )
      .optional(),
  })
  .strict();

export type EnterpriseProfileFile = z.infer<
  typeof enterpriseProfileFileSchema
>;

export function parseEnterpriseProfile(
  raw: unknown,
): EnterpriseProfile {
  const parsed =
    enterpriseProfileFileSchema.safeParse(
      raw,
    );

  if (!parsed.success) {
    /*
      Reported as the field paths that failed rather than a stack, because
      the person fixing this is editing a JSON file and needs to know which
      line to look at.
    */
    const problems = parsed.error.issues
      .map(
        (issue) =>
          `  ${
            issue.path.join(".") || "(root)"
          }: ${issue.message}`,
      )
      .join("\n");

    throw new Error(
      `Environment profile is not valid:\n${problems}`,
    );
  }

  const file = parsed.data;

  /*
    Department subnets have to be distinct or two departments share an
    address range, and "which department is this host in" stops having an
    answer -- which is the question half the scenarios turn on.
  */
  if (file.departments) {
    const octets = new Set(
      file.departments.map(
        (department) =>
          department.subnetOctet,
      ),
    );

    if (
      octets.size !==
      file.departments.length
    ) {
      throw new Error(
        "Environment profile gives two departments the same subnetOctet; addresses would not identify a department.",
      );
    }

    const codes = new Set(
      file.departments.map(
        (department) =>
          department.hostCode.toUpperCase(),
      ),
    );

    if (
      codes.size !==
      file.departments.length
    ) {
      throw new Error(
        "Environment profile gives two departments the same hostCode; hostnames would collide.",
      );
    }
  }

  return {
    ...DEFAULT_ENTERPRISE_PROFILE,
    ...file,
  };
}
