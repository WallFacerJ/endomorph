import type {
  EntityId,
} from "@polymorph/domain";

import type {
  WorldState,
} from "./worldState";

export type RelationshipIndex = Readonly<
  Record<EntityId, readonly EntityId[]>
>;

export interface WorldRelationshipIndexes {
  usersByOrganizationId:
    RelationshipIndex;

  accountsByOrganizationId:
    RelationshipIndex;

  accountsByUserId:
    RelationshipIndex;

  devicesByOrganizationId:
    RelationshipIndex;

  devicesByOwnerUserId:
    RelationshipIndex;

  filesByOrganizationId:
    RelationshipIndex;

  filesByOwnerUserId:
    RelationshipIndex;

  filesByDeviceId:
    RelationshipIndex;

  applicationsByOrganizationId:
    RelationshipIndex;

  sessionsByAccountId:
    RelationshipIndex;

  sessionsByDeviceId:
    RelationshipIndex;

  sessionsByApplicationId:
    RelationshipIndex;
}

type MutableRelationshipIndex =
  Record<EntityId, EntityId[]>;

function appendRelationship(
  index: MutableRelationshipIndex,
  parentId: EntityId | undefined,
  childId: EntityId,
): void {
  if (parentId === undefined) {
    return;
  }

  const existing = index[parentId];

  if (existing) {
    existing.push(childId);
    return;
  }

  index[parentId] = [childId];
}

function finalizeIndex(
  index: MutableRelationshipIndex,
): RelationshipIndex {
  return Object.fromEntries(
    Object.entries(index)
      .sort(([left], [right]) =>
        left.localeCompare(right),
      )
      .map(([parentId, childIds]) => [
        parentId,
        [...childIds].sort((left, right) =>
          left.localeCompare(right),
        ),
      ]),
  );
}

function sortedEntities<T extends { id: EntityId }>(
  entities: Readonly<Record<EntityId, T>>,
): T[] {
  return Object.values(entities).sort(
    (left, right) =>
      left.id.localeCompare(right.id),
  );
}

export function buildWorldRelationshipIndexes(
  world: WorldState,
): WorldRelationshipIndexes {
  const usersByOrganizationId:
    MutableRelationshipIndex = {};
  const accountsByOrganizationId:
    MutableRelationshipIndex = {};
  const accountsByUserId:
    MutableRelationshipIndex = {};
  const devicesByOrganizationId:
    MutableRelationshipIndex = {};
  const devicesByOwnerUserId:
    MutableRelationshipIndex = {};
  const filesByOrganizationId:
    MutableRelationshipIndex = {};
  const filesByOwnerUserId:
    MutableRelationshipIndex = {};
  const filesByDeviceId:
    MutableRelationshipIndex = {};
  const applicationsByOrganizationId:
    MutableRelationshipIndex = {};
  const sessionsByAccountId:
    MutableRelationshipIndex = {};
  const sessionsByDeviceId:
    MutableRelationshipIndex = {};
  const sessionsByApplicationId:
    MutableRelationshipIndex = {};

  for (
    const user of sortedEntities(
      world.users,
    )
  ) {
    appendRelationship(
      usersByOrganizationId,
      user.organizationId,
      user.id,
    );
  }

  for (
    const account of sortedEntities(
      world.accounts,
    )
  ) {
    appendRelationship(
      accountsByOrganizationId,
      account.organizationId,
      account.id,
    );
    appendRelationship(
      accountsByUserId,
      account.userId,
      account.id,
    );
  }

  for (
    const device of sortedEntities(
      world.devices,
    )
  ) {
    appendRelationship(
      devicesByOrganizationId,
      device.organizationId,
      device.id,
    );
    appendRelationship(
      devicesByOwnerUserId,
      device.ownerUserId,
      device.id,
    );
  }

  for (
    const file of sortedEntities(
      world.files,
    )
  ) {
    appendRelationship(
      filesByOrganizationId,
      file.organizationId,
      file.id,
    );
    appendRelationship(
      filesByOwnerUserId,
      file.ownerUserId,
      file.id,
    );
    appendRelationship(
      filesByDeviceId,
      file.deviceId,
      file.id,
    );
  }

  for (
    const application of sortedEntities(
      world.applications,
    )
  ) {
    appendRelationship(
      applicationsByOrganizationId,
      application.organizationId,
      application.id,
    );
  }

  for (
    const session of sortedEntities(
      world.sessions,
    )
  ) {
    appendRelationship(
      sessionsByAccountId,
      session.accountId,
      session.id,
    );
    appendRelationship(
      sessionsByDeviceId,
      session.deviceId,
      session.id,
    );
    appendRelationship(
      sessionsByApplicationId,
      session.applicationId,
      session.id,
    );
  }

  return {
    usersByOrganizationId:
      finalizeIndex(
        usersByOrganizationId,
      ),
    accountsByOrganizationId:
      finalizeIndex(
        accountsByOrganizationId,
      ),
    accountsByUserId:
      finalizeIndex(accountsByUserId),
    devicesByOrganizationId:
      finalizeIndex(
        devicesByOrganizationId,
      ),
    devicesByOwnerUserId:
      finalizeIndex(
        devicesByOwnerUserId,
      ),
    filesByOrganizationId:
      finalizeIndex(
        filesByOrganizationId,
      ),
    filesByOwnerUserId:
      finalizeIndex(
        filesByOwnerUserId,
      ),
    filesByDeviceId:
      finalizeIndex(filesByDeviceId),
    applicationsByOrganizationId:
      finalizeIndex(
        applicationsByOrganizationId,
      ),
    sessionsByAccountId:
      finalizeIndex(
        sessionsByAccountId,
      ),
    sessionsByDeviceId:
      finalizeIndex(
        sessionsByDeviceId,
      ),
    sessionsByApplicationId:
      finalizeIndex(
        sessionsByApplicationId,
      ),
  };
}
