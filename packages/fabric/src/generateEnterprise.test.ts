import {
  describe,
  expect,
  it,
} from "vitest";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

import {
  DEPARTMENT_PROFILES,
} from "./nameLibrary.js";

describe("generateEnterprise", () => {
  describe("determinism", () => {
    it("produces an identical enterprise from the same seed", () => {
      expect(
        generateEnterprise({
          seed: 4242,
        }),
      ).toEqual(
        generateEnterprise({
          seed: 4242,
        }),
      );
    });

    it("produces a different enterprise from a different seed", () => {
      const first = generateEnterprise({
        seed: 4242,
      });

      const second =
        generateEnterprise({
          seed: 9999,
        });

      expect(
        first.users.map(
          (user) => user.displayName,
        ),
      ).not.toEqual(
        second.users.map(
          (user) => user.displayName,
        ),
      );
    });

    it("keeps existing staff stable when headcount grows", () => {
      // The payoff of the splittable cursor: hiring one more person must not
      // rewrite everyone else's identity, device, or account.
      const smaller = generateEnterprise(
        { seed: 4242, headcount: 60 },
      );

      const larger = generateEnterprise({
        seed: 4242,
        headcount: 61,
      });

      const smallerFinance =
        smaller.users.filter(
          (user) =>
            user.department ===
            "Finance",
        );

      const largerFinance =
        larger.users.filter(
          (user) =>
            user.department ===
            "Finance",
        );

      const shared = Math.min(
        smallerFinance.length,
        largerFinance.length,
      );

      expect(shared).toBeGreaterThan(0);

      expect(
        largerFinance
          .slice(0, shared)
          .map(
            (user) => user.displayName,
          ),
      ).toEqual(
        smallerFinance
          .slice(0, shared)
          .map(
            (user) => user.displayName,
          ),
      );
    });
  });

  describe("scale", () => {
    it("generates the requested headcount", () => {
      for (const headcount of [
        24, 60, 120, 400,
      ]) {
        expect(
          generateEnterprise({
            seed: 1,
            headcount,
          }).users,
        ).toHaveLength(headcount);
      }
    });

    it("produces an enterprise far larger than a hand-authored scenario", () => {
      // The shipped v1 scenarios topped out at 15 entities. The generator
      // exists because the Phase 1 exit criteria need orders more.
      const enterprise =
        generateEnterprise();

      const total =
        enterprise.organizations
          .length +
        enterprise.users.length +
        enterprise.accounts.length +
        enterprise.devices.length +
        enterprise.applications.length +
        enterprise.files.length;

      expect(
        total,
      ).toBeGreaterThan(400);
    });

    it("staffs every department", () => {
      const enterprise =
        generateEnterprise({
          seed: 7,
          headcount: 24,
        });

      const staffed = new Set(
        enterprise.users.map(
          (user) => user.department,
        ),
      );

      expect(staffed.size).toBe(
        DEPARTMENT_PROFILES.length,
      );
    });

    it("rejects an invalid profile", () => {
      expect(() =>
        generateEnterprise({
          headcount: 0,
        }),
      ).toThrow();

      expect(() =>
        generateEnterprise({
          privilegedAccountRate: 1.4,
        }),
      ).toThrow();

      expect(() =>
        generateEnterprise({
          startTime: "not-a-date",
        }),
      ).toThrow();
    });
  });

  describe("referential integrity", () => {
    const enterprise =
      generateEnterprise();

    it("assigns every entity a unique id", () => {
      for (const collection of [
        enterprise.users,
        enterprise.accounts,
        enterprise.devices,
        enterprise.applications,
        enterprise.files,
      ]) {
        const ids = collection.map(
          (entity) => entity.id,
        );

        expect(
          new Set(ids).size,
        ).toBe(ids.length);
      }
    });

    it("gives every user a unique email", () => {
      const emails =
        enterprise.users.map(
          (user) => user.email,
        );

      expect(new Set(emails).size).toBe(
        emails.length,
      );
    });

    it("resolves every account back to a real user", () => {
      const userIds = new Set(
        enterprise.users.map(
          (user) => user.id,
        ),
      );

      for (const account of enterprise.accounts) {
        expect(
          userIds.has(account.userId),
        ).toBe(true);
      }
    });

    it("keeps user.accountIds and accounts mutually consistent", () => {
      const accountsById = new Map(
        enterprise.accounts.map(
          (account) => [
            account.id,
            account,
          ],
        ),
      );

      for (const user of enterprise.users) {
        expect(
          user.accountIds.length,
        ).toBeGreaterThan(0);

        for (const accountId of user.accountIds) {
          const account =
            accountsById.get(accountId);

          expect(
            account,
          ).toBeDefined();

          expect(account?.userId).toBe(
            user.id,
          );
        }
      }
    });

    it("keeps user.deviceIds and devices mutually consistent", () => {
      const devicesById = new Map(
        enterprise.devices.map(
          (device) => [
            device.id,
            device,
          ],
        ),
      );

      for (const user of enterprise.users) {
        for (const deviceId of user.deviceIds) {
          expect(
            devicesById.get(deviceId)
              ?.ownerUserId,
          ).toBe(user.id);
        }
      }
    });

    it("scopes every entity to the generated organization", () => {
      const organizationId =
        enterprise.organizations[0].id;

      for (const entity of [
        ...enterprise.users,
        ...enterprise.accounts,
        ...enterprise.devices,
        ...enterprise.applications,
        ...enterprise.files,
      ]) {
        expect(
          entity.organizationId,
        ).toBe(organizationId);
      }
    });

    it("points every file owner at a real user", () => {
      const userIds = new Set(
        enterprise.users.map(
          (user) => user.id,
        ),
      );

      for (const file of enterprise.files) {
        if (file.ownerUserId) {
          expect(
            userIds.has(
              file.ownerUserId,
            ),
          ).toBe(true);
        }
      }
    });
  });

  describe("realism", () => {
    const enterprise =
      generateEnterprise();

    it("puts workstations on their department subnet", () => {
      const departmentByName = new Map(
        DEPARTMENT_PROFILES.map(
          (department) => [
            department.name,
            department,
          ],
        ),
      );

      const usersById = new Map(
        enterprise.users.map((user) => [
          user.id,
          user,
        ]),
      );

      for (const device of enterprise.devices) {
        if (!device.ownerUserId) {
          continue;
        }

        const owner = usersById.get(
          device.ownerUserId,
        );

        const department =
          departmentByName.get(
            owner?.department ?? "",
          );

        expect(
          device.ipAddresses[0],
        ).toMatch(
          new RegExp(
            `^10\\.${department?.subnetOctet}\\.`,
          ),
        );
      }
    });

    it("keeps domain controllers and the SMB file server on Windows", () => {
      // The generated file paths are UNC shares, so a Linux FS-01 would be
      // internally incoherent.
      for (const hostname of [
        "DC-01",
        "DC-02",
        "FS-01",
      ]) {
        const server =
          enterprise.devices.find(
            (device) =>
              device.hostname ===
              hostname,
          );

        expect(
          server?.operatingSystem,
        ).toMatch(/^Windows Server/);
      }
    });

    it("issues privileged accounts to only a minority of staff", () => {
      const ratio =
        enterprise.privilegedAccountIds
          .length /
        enterprise.users.length;

      expect(ratio).toBeGreaterThan(0);
      expect(ratio).toBeLessThan(0.4);
    });

    it("gives privileged accounts a distinct username and elevated role", () => {
      const accountsById = new Map(
        enterprise.accounts.map(
          (account) => [
            account.id,
            account,
          ],
        ),
      );

      for (const accountId of enterprise.privilegedAccountIds) {
        const account =
          accountsById.get(accountId);

        expect(
          account?.username,
        ).toMatch(/^adm-/);

        expect(
          account?.roles.length,
        ).toBeGreaterThan(1);
      }
    });

    it("includes dormant and disabled staff as investigation noise", () => {
      const statuses = new Set(
        enterprise.users.map(
          (user) => user.status,
        ),
      );

      expect(
        statuses.has("active"),
      ).toBe(true);

      expect(statuses.size).toBeGreaterThan(
        1,
      );
    });

    it("classifies sensitive documents as high-value assets", () => {
      const restricted =
        enterprise.files.filter(
          (file) =>
            file.classification ===
            "restricted",
        );

      expect(
        restricted.length,
      ).toBeGreaterThan(0);

      for (const file of restricted) {
        expect(
          enterprise.assetContext[
            file.id
          ]?.criticality,
        ).toBe("severe");
      }
    });

    it("gives every generated entity business context", () => {
      for (const entity of [
        ...enterprise.users,
        ...enterprise.devices,
        ...enterprise.applications,
        ...enterprise.files,
      ]) {
        expect(
          enterprise.assetContext[
            entity.id
          ],
        ).toBeDefined();
      }
    });

    it("defines a network segment per department plus the datacenter", () => {
      expect(
        enterprise.segments,
      ).toHaveLength(
        DEPARTMENT_PROFILES.length + 1,
      );

      for (const segment of enterprise.segments) {
        expect(segment.cidr).toMatch(
          /^10\.\d+\.0\.0\/16$/,
        );
      }
    });
  });
});
