import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseEnterpriseProfile,
} from "./profileFile.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

const department = {
  name: "Dispatch",
  weight: 30,
  subnetOctet: 10,
  hostCode: "DSP",
  titles: ["Dispatcher"],
  baseRoles: ["domain-users"],
  criticality: "high" as const,
};

describe("parseEnterpriseProfile", () => {
  it("fills everything the file leaves out", () => {
    // A profile that sets only a domain is a legitimate profile.
    const profile = parseEnterpriseProfile(
      { domain: "northwind.internal" },
    );

    expect(profile.domain).toBe(
      "northwind.internal",
    );

    expect(
      profile.headcount,
    ).toBeGreaterThan(0);

    expect(
      profile.departments.length,
    ).toBeGreaterThan(0);
  });

  it("refuses two departments sharing a subnet", () => {
    /*
      Addresses would stop identifying a department, which is the question
      half the scenarios turn on -- "is this account signing in from its own
      department's range" has no answer if two departments share one.
    */
    expect(() =>
      parseEnterpriseProfile({
        departments: [
          department,
          {
            ...department,
            name: "Warehouse",
            hostCode: "WHS",
          },
        ],
      }),
    ).toThrow(/same subnetOctet/);
  });

  it("refuses two departments sharing a host code", () => {
    expect(() =>
      parseEnterpriseProfile({
        departments: [
          department,
          {
            ...department,
            name: "Warehouse",
            subnetOctet: 11,
          },
        ],
      }),
    ).toThrow(/same hostCode/);
  });

  it("refuses a hostname pattern with no ordinal", () => {
    // Every host in a department would be named the same thing.
    expect(() =>
      parseEnterpriseProfile({
        hostnamePattern: "{code}-DESKTOP",
      }),
    ).toThrow(/\{n\}/);
  });

  it("names the field that failed", () => {
    /*
      The person fixing this is editing a JSON file by hand and needs to know
      which line to look at, not a stack trace.
    */
    expect(() =>
      parseEnterpriseProfile({
        headcount: -5,
      }),
    ).toThrow(/headcount/);
  });

  it("rejects a key it does not recognise", () => {
    // A silently ignored typo produces an estate that looks nearly right,
    // which is the hardest kind of wrong to notice in generated data.
    expect(() =>
      parseEnterpriseProfile({
        headcont: 200,
      }),
    ).toThrow();
  });

  it("produces an estate shaped like the profile", () => {
    const profile = parseEnterpriseProfile(
      {
        organizationName:
          "Northwind Logistics",
        headcount: 40,
        workstationSubnetPrefix: "172.18",
        hostnamePattern: "NW{code}{n}",
        departments: [department],
      },
    );

    const enterprise =
      generateEnterprise(profile);

    const workstations =
      enterprise.devices.filter(
        (device) => device.ownerUserId,
      );

    expect(
      workstations.length,
    ).toBeGreaterThan(0);

    for (const device of workstations) {
      expect(device.hostname).toMatch(
        /^NWDSP\d{3}$/,
      );

      expect(
        device.ipAddresses[0],
      ).toMatch(/^172\.18\.10\./);
    }
  });

  it("stays deterministic under a custom profile", () => {
    // The property everything commercial rests on has to survive the estate
    // being reshaped, or a client-specific corpus is not reproducible.
    const profile = parseEnterpriseProfile(
      {
        headcount: 30,
        departments: [department],
      },
    );

    expect(
      generateEnterprise(profile)
        .devices.map(
          (device) => device.hostname,
        ),
    ).toEqual(
      generateEnterprise(profile)
        .devices.map(
          (device) => device.hostname,
        ),
    );
  });
});
