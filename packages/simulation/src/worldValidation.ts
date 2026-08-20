import type {
  EntityId,
} from "@polymorph/domain";

import type {
  WorldState,
} from "./worldState";

export type WorldEntityType =
  | "organization"
  | "user"
  | "account"
  | "device"
  | "file"
  | "application"
  | "session";

export type WorldValidationCode =
  | "collection_key_mismatch"
  | "missing_reference"
  | "organization_mismatch"
  | "relationship_mismatch"
  | "temporal_invariant";

export interface WorldValidationIssue {
  code: WorldValidationCode;

  entityType: WorldEntityType;

  entityId: EntityId;

  field: string;

  referencedId?: EntityId;

  message: string;
}

function sortedEntries<T extends { id: EntityId }>(
  entities: Readonly<Record<EntityId, T>>,
): Array<[EntityId, T]> {
  return Object.entries(entities).sort(
    ([left], [right]) =>
      left.localeCompare(right),
  );
}

function addCollectionKeyIssues<T extends {
  id: EntityId;
}>(
  issues: WorldValidationIssue[],
  entityType: WorldEntityType,
  entities: Readonly<Record<EntityId, T>>,
): void {
  for (
    const [key, entity] of
      sortedEntries(entities)
  ) {
    if (key === entity.id) {
      continue;
    }

    issues.push({
      code: "collection_key_mismatch",
      entityType,
      entityId: entity.id,
      field: "id",
      referencedId: key,
      message:
        `${entityType} ${entity.id} is stored under key ${key}.`,
    });
  }
}

function addMissingReference(
  issues: WorldValidationIssue[],
  entityType: WorldEntityType,
  entityId: EntityId,
  field: string,
  referencedId: EntityId,
  referencedType: WorldEntityType,
): void {
  issues.push({
    code: "missing_reference",
    entityType,
    entityId,
    field,
    referencedId,
    message:
      `${entityType} ${entityId} references missing ${referencedType} ${referencedId} via ${field}.`,
  });
}

function addOrganizationMismatch(
  issues: WorldValidationIssue[],
  entityType: WorldEntityType,
  entityId: EntityId,
  field: string,
  referencedId: EntityId,
): void {
  issues.push({
    code: "organization_mismatch",
    entityType,
    entityId,
    field,
    referencedId,
    message:
      `${entityType} ${entityId} references ${referencedId} in a different organization via ${field}.`,
  });
}

function addRelationshipMismatch(
  issues: WorldValidationIssue[],
  entityType: WorldEntityType,
  entityId: EntityId,
  field: string,
  referencedId: EntityId,
  message: string,
): void {
  issues.push({
    code: "relationship_mismatch",
    entityType,
    entityId,
    field,
    referencedId,
    message,
  });
}

export function validateWorldState(
  world: WorldState,
): readonly WorldValidationIssue[] {
  const issues: WorldValidationIssue[] = [];

  addCollectionKeyIssues(
    issues,
    "organization",
    world.organizations,
  );
  addCollectionKeyIssues(
    issues,
    "user",
    world.users,
  );
  addCollectionKeyIssues(
    issues,
    "account",
    world.accounts,
  );
  addCollectionKeyIssues(
    issues,
    "device",
    world.devices,
  );
  addCollectionKeyIssues(
    issues,
    "file",
    world.files,
  );
  addCollectionKeyIssues(
    issues,
    "application",
    world.applications,
  );
  addCollectionKeyIssues(
    issues,
    "session",
    world.sessions,
  );

  for (
    const [, user] of sortedEntries(
      world.users,
    )
  ) {
    if (
      !world.organizations[
        user.organizationId
      ]
    ) {
      addMissingReference(
        issues,
        "user",
        user.id,
        "organizationId",
        user.organizationId,
        "organization",
      );
    }

    for (
      const accountId of [
        ...user.accountIds,
      ].sort()
    ) {
      const account =
        world.accounts[accountId];

      if (!account) {
        addMissingReference(
          issues,
          "user",
          user.id,
          "accountIds",
          accountId,
          "account",
        );
        continue;
      }

      if (account.userId !== user.id) {
        addRelationshipMismatch(
          issues,
          "user",
          user.id,
          "accountIds",
          accountId,
          `User ${user.id} lists account ${accountId}, but the account belongs to user ${account.userId}.`,
        );
      }

      if (
        account.organizationId !==
        user.organizationId
      ) {
        addOrganizationMismatch(
          issues,
          "user",
          user.id,
          "accountIds",
          accountId,
        );
      }
    }

    for (
      const deviceId of [
        ...user.deviceIds,
      ].sort()
    ) {
      const device =
        world.devices[deviceId];

      if (!device) {
        addMissingReference(
          issues,
          "user",
          user.id,
          "deviceIds",
          deviceId,
          "device",
        );
        continue;
      }

      if (
        device.ownerUserId !== user.id
      ) {
        addRelationshipMismatch(
          issues,
          "user",
          user.id,
          "deviceIds",
          deviceId,
          `User ${user.id} lists device ${deviceId}, but the device owner is ${device.ownerUserId ?? "unassigned"}.`,
        );
      }

      if (
        device.organizationId !==
        user.organizationId
      ) {
        addOrganizationMismatch(
          issues,
          "user",
          user.id,
          "deviceIds",
          deviceId,
        );
      }
    }
  }

  for (
    const [, account] of sortedEntries(
      world.accounts,
    )
  ) {
    if (
      !world.organizations[
        account.organizationId
      ]
    ) {
      addMissingReference(
        issues,
        "account",
        account.id,
        "organizationId",
        account.organizationId,
        "organization",
      );
    }

    const user =
      world.users[account.userId];

    if (!user) {
      addMissingReference(
        issues,
        "account",
        account.id,
        "userId",
        account.userId,
        "user",
      );
      continue;
    }

    if (
      user.organizationId !==
      account.organizationId
    ) {
      addOrganizationMismatch(
        issues,
        "account",
        account.id,
        "userId",
        user.id,
      );
    }

    if (
      !user.accountIds.includes(
        account.id,
      )
    ) {
      addRelationshipMismatch(
        issues,
        "account",
        account.id,
        "userId",
        user.id,
        `Account ${account.id} belongs to user ${user.id}, but that user does not list the account.`,
      );
    }
  }

  for (
    const [, device] of sortedEntries(
      world.devices,
    )
  ) {
    if (
      !world.organizations[
        device.organizationId
      ]
    ) {
      addMissingReference(
        issues,
        "device",
        device.id,
        "organizationId",
        device.organizationId,
        "organization",
      );
    }

    if (!device.ownerUserId) {
      continue;
    }

    const user =
      world.users[device.ownerUserId];

    if (!user) {
      addMissingReference(
        issues,
        "device",
        device.id,
        "ownerUserId",
        device.ownerUserId,
        "user",
      );
      continue;
    }

    if (
      user.organizationId !==
      device.organizationId
    ) {
      addOrganizationMismatch(
        issues,
        "device",
        device.id,
        "ownerUserId",
        user.id,
      );
    }

    if (
      !user.deviceIds.includes(
        device.id,
      )
    ) {
      addRelationshipMismatch(
        issues,
        "device",
        device.id,
        "ownerUserId",
        user.id,
        `Device ${device.id} belongs to user ${user.id}, but that user does not list the device.`,
      );
    }
  }

  for (
    const [, file] of sortedEntries(
      world.files,
    )
  ) {
    if (
      !world.organizations[
        file.organizationId
      ]
    ) {
      addMissingReference(
        issues,
        "file",
        file.id,
        "organizationId",
        file.organizationId,
        "organization",
      );
    }

    if (file.ownerUserId) {
      const owner =
        world.users[file.ownerUserId];

      if (!owner) {
        addMissingReference(
          issues,
          "file",
          file.id,
          "ownerUserId",
          file.ownerUserId,
          "user",
        );
      } else if (
        owner.organizationId !==
        file.organizationId
      ) {
        addOrganizationMismatch(
          issues,
          "file",
          file.id,
          "ownerUserId",
          owner.id,
        );
      }
    }

    if (file.deviceId) {
      const device =
        world.devices[file.deviceId];

      if (!device) {
        addMissingReference(
          issues,
          "file",
          file.id,
          "deviceId",
          file.deviceId,
          "device",
        );
      } else if (
        device.organizationId !==
        file.organizationId
      ) {
        addOrganizationMismatch(
          issues,
          "file",
          file.id,
          "deviceId",
          device.id,
        );
      }
    }
  }

  for (
    const [, application] of
      sortedEntries(
        world.applications,
      )
  ) {
    if (
      !world.organizations[
        application.organizationId
      ]
    ) {
      addMissingReference(
        issues,
        "application",
        application.id,
        "organizationId",
        application.organizationId,
        "organization",
      );
    }
  }

  for (
    const [, session] of sortedEntries(
      world.sessions,
    )
  ) {
    const account =
      world.accounts[
        session.accountId
      ];

    if (!account) {
      addMissingReference(
        issues,
        "session",
        session.id,
        "accountId",
        session.accountId,
        "account",
      );
    }

    if (session.deviceId) {
      const device =
        world.devices[session.deviceId];

      if (!device) {
        addMissingReference(
          issues,
          "session",
          session.id,
          "deviceId",
          session.deviceId,
          "device",
        );
      } else if (
        account &&
        device.organizationId !==
          account.organizationId
      ) {
        addOrganizationMismatch(
          issues,
          "session",
          session.id,
          "deviceId",
          device.id,
        );
      }
    }

    if (session.applicationId) {
      const application =
        world.applications[
          session.applicationId
        ];

      if (!application) {
        addMissingReference(
          issues,
          "session",
          session.id,
          "applicationId",
          session.applicationId,
          "application",
        );
      } else if (
        account &&
        application.organizationId !==
          account.organizationId
      ) {
        addOrganizationMismatch(
          issues,
          "session",
          session.id,
          "applicationId",
          application.id,
        );
      }
    }

    if (session.endedAt) {
      const startedAt =
        Date.parse(session.startedAt);
      const endedAt =
        Date.parse(session.endedAt);

      if (
        Number.isFinite(startedAt) &&
        Number.isFinite(endedAt) &&
        endedAt < startedAt
      ) {
        issues.push({
          code: "temporal_invariant",
          entityType: "session",
          entityId: session.id,
          field: "endedAt",
          message:
            `Session ${session.id} ends before it starts.`,
        });
      }
    }
  }

  return issues;
}
