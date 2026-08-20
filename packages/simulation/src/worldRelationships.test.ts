import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
  exampleApplication,
  exampleDevice,
  exampleFile,
  exampleOrganization,
  exampleSession,
  exampleUser,
} from "@polymorph/domain";

import {
  createWorldState,
} from "./worldState";

import {
  buildWorldRelationshipIndexes,
} from "./worldRelationships";

import {
  validateWorldState,
} from "./worldValidation";

function createExampleWorld() {
  return createWorldState({
    simulationTime:
      "2026-08-20T12:00:00Z",
    organizations: [
      exampleOrganization,
    ],
    users: [exampleUser],
    accounts: [exampleAccount],
    devices: [exampleDevice],
    files: [exampleFile],
    applications: [
      exampleApplication,
    ],
    sessions: [exampleSession],
  });
}

describe(
  "buildWorldRelationshipIndexes",
  () => {
    it("builds deterministic derived indexes for existing relationships", () => {
      const indexes =
        buildWorldRelationshipIndexes(
          createExampleWorld(),
        );

      expect(indexes)
        .toMatchObject({
          usersByOrganizationId: {
            [exampleOrganization.id]: [
              exampleUser.id,
            ],
          },
          accountsByOrganizationId: {
            [exampleOrganization.id]: [
              exampleAccount.id,
            ],
          },
          accountsByUserId: {
            [exampleUser.id]: [
              exampleAccount.id,
            ],
          },
          devicesByOwnerUserId: {
            [exampleUser.id]: [
              exampleDevice.id,
            ],
          },
          filesByOwnerUserId: {
            [exampleUser.id]: [
              exampleFile.id,
            ],
          },
          filesByDeviceId: {
            [exampleDevice.id]: [
              exampleFile.id,
            ],
          },
          sessionsByAccountId: {
            [exampleAccount.id]: [
              exampleSession.id,
            ],
          },
          sessionsByDeviceId: {
            [exampleDevice.id]: [
              exampleSession.id,
            ],
          },
          sessionsByApplicationId: {
            [exampleApplication.id]: [
              exampleSession.id,
            ],
          },
        });
    });

    it("sorts relationship ids independently of seed insertion order", () => {
      const accountA = {
        ...exampleAccount,
        id: "account-a",
      };
      const accountB = {
        ...exampleAccount,
        id: "account-b",
      };

      const world = createWorldState({
        simulationTime:
          "2026-08-20T12:00:00Z",
        accounts: [
          accountB,
          accountA,
        ],
      });

      expect(
        buildWorldRelationshipIndexes(
          world,
        ).accountsByUserId[
          exampleUser.id
        ],
      ).toEqual([
        "account-a",
        "account-b",
      ]);
    });

    it("omits undefined optional relationships", () => {
      const world = createWorldState({
        simulationTime:
          "2026-08-20T12:00:00Z",
        devices: [
          {
            ...exampleDevice,
            ownerUserId: undefined,
          },
        ],
        files: [
          {
            ...exampleFile,
            ownerUserId: undefined,
            deviceId: undefined,
          },
        ],
        sessions: [
          {
            ...exampleSession,
            deviceId: undefined,
            applicationId: undefined,
          },
        ],
      });

      const indexes =
        buildWorldRelationshipIndexes(
          world,
        );

      expect(
        indexes.devicesByOwnerUserId,
      ).toEqual({});
      expect(
        indexes.filesByOwnerUserId,
      ).toEqual({});
      expect(indexes.filesByDeviceId)
        .toEqual({});
      expect(
        indexes.sessionsByDeviceId,
      ).toEqual({});
      expect(
        indexes.sessionsByApplicationId,
      ).toEqual({});
    });
  },
);

describe("validateWorldState", () => {
  it("accepts the interconnected example world", () => {
    expect(
      validateWorldState(
        createExampleWorld(),
      ),
    ).toEqual([]);
  });

  it("reports missing references with actionable fields", () => {
    const world = createWorldState({
      simulationTime:
        "2026-08-20T12:00:00Z",
      users: [
        {
          ...exampleUser,
          organizationId:
            "org-missing",
          accountIds: [
            "account-missing",
          ],
          deviceIds: [
            "device-missing",
          ],
        },
      ],
      sessions: [
        {
          ...exampleSession,
          accountId:
            "account-missing",
          deviceId:
            "device-missing",
          applicationId:
            "app-missing",
        },
      ],
    });

    const issues =
      validateWorldState(world);

    expect(issues)
      .toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            code: "missing_reference",
            entityType: "user",
            field: "organizationId",
            referencedId:
              "org-missing",
          }),
          expect.objectContaining({
            code: "missing_reference",
            entityType: "user",
            field: "accountIds",
            referencedId:
              "account-missing",
          }),
          expect.objectContaining({
            code: "missing_reference",
            entityType: "session",
            field: "applicationId",
            referencedId: "app-missing",
          }),
        ]),
      );
  });

  it("reports bidirectional and organization mismatches", () => {
    const secondOrganization = {
      ...exampleOrganization,
      id: "org-other",
      name: "Other Org",
    };

    const mismatchedDevice = {
      ...exampleDevice,
      organizationId:
        secondOrganization.id,
      ownerUserId: exampleUser.id,
    };

    const world = createWorldState({
      simulationTime:
        "2026-08-20T12:00:00Z",
      organizations: [
        exampleOrganization,
        secondOrganization,
      ],
      users: [
        {
          ...exampleUser,
          accountIds: [],
          deviceIds: [
            mismatchedDevice.id,
          ],
        },
      ],
      accounts: [exampleAccount],
      devices: [mismatchedDevice],
    });

    const issues =
      validateWorldState(world);

    expect(issues)
      .toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            code:
              "relationship_mismatch",
            entityType: "account",
            field: "userId",
            referencedId:
              exampleUser.id,
          }),
          expect.objectContaining({
            code:
              "organization_mismatch",
            entityType: "user",
            field: "deviceIds",
            referencedId:
              exampleDevice.id,
          }),
          expect.objectContaining({
            code:
              "organization_mismatch",
            entityType: "device",
            field: "ownerUserId",
            referencedId:
              exampleUser.id,
          }),
        ]),
      );
  });

  it("reports sessions that end before they start", () => {
    const world = createWorldState({
      simulationTime:
        "2026-08-20T12:00:00Z",
      organizations: [
        exampleOrganization,
      ],
      users: [exampleUser],
      accounts: [exampleAccount],
      devices: [exampleDevice],
      applications: [
        exampleApplication,
      ],
      sessions: [
        {
          ...exampleSession,
          endedAt:
            "2026-08-18T09:00:00Z",
        },
      ],
    });

    expect(
      validateWorldState(world),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code:
            "temporal_invariant",
          entityType: "session",
          entityId:
            exampleSession.id,
          field: "endedAt",
        }),
      ]),
    );
  });
});
