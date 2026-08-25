import type {
  EntityId,
} from "@endomorph/domain";

import {
  assertNever,
} from "./assertNever";

import type {
  SimulationEvent,
} from "./simulationEvent";

import type {
  WorldState,
} from "./worldState";

function requireEntity<T>(
  entities: Record<EntityId, T>,
  id: EntityId,
  label: string,
): T {
  const entity = entities[id];

  if (!entity) {
    throw new Error(
      `${label} not found: ${id}`,
    );
  }

  return entity;
}

export function validateSimulationEvent(
  world: WorldState,
  event: SimulationEvent,
): void {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED": {
      const account =
        requireEntity(
          world.accounts,
          event.payload.accountId,
          "Account",
        );

      requireEntity(
        world.users,
        event.payload.userId,
        "User",
      );

      if (
        account.userId !==
        event.payload.userId
      ) {
        throw new Error(
          `Account ${account.id} does not belong to user ${event.payload.userId}`,
        );
      }

      if (event.payload.deviceId) {
        requireEntity(
          world.devices,
          event.payload.deviceId,
          "Device",
        );
      }

      if (
        event.payload.applicationId
      ) {
        requireEntity(
          world.applications,
          event.payload.applicationId,
          "Application",
        );
      }

      return;
    }

    case "AUTH_LOGIN_FAILED": {
      if (event.payload.deviceId) {
        requireEntity(
          world.devices,
          event.payload.deviceId,
          "Device",
        );
      }

      if (
        event.payload.applicationId
      ) {
        requireEntity(
          world.applications,
          event.payload.applicationId,
          "Application",
        );
      }

      return;
    }

    case "ACCOUNT_DISABLED":
    case "ACCOUNT_ENABLED":
      requireEntity(
        world.accounts,
        event.payload.accountId,
        "Account",
      );

      return;

    case "ROLE_GRANTED": {
      requireEntity(
        world.accounts,
        event.payload.accountId,
        "Account",
      );

      if (
        event.payload.role.trim()
          .length === 0
      ) {
        throw new Error(
          `Role grant ${event.id} names no role.`,
        );
      }

      if (event.payload.applicationId) {
        requireEntity(
          world.applications,
          event.payload.applicationId,
          "Application",
        );
      }

      return;
    }

    case "SESSION_STARTED": {
      const {
        sessionId,
        accountId,
        deviceId,
        applicationId,
      } = event.payload;

      if (world.sessions[sessionId]) {
        throw new Error(
          `Session already exists: ${sessionId}`,
        );
      }

      requireEntity(
        world.accounts,
        accountId,
        "Account",
      );

      if (deviceId) {
        requireEntity(
          world.devices,
          deviceId,
          "Device",
        );
      }

      if (applicationId) {
        requireEntity(
          world.applications,
          applicationId,
          "Application",
        );
      }

      return;
    }

    case "SESSION_REVOKED":
      requireEntity(
        world.sessions,
        event.payload.sessionId,
        "Session",
      );

      return;

    case "PROCESS_STARTED":
      requireEntity(
        world.devices,
        event.payload.deviceId,
        "Device",
      );

      if (event.payload.accountId) {
        requireEntity(
          world.accounts,
          event.payload.accountId,
          "Account",
        );
      }

      return;

    case "FILE_ACCESSED":
      requireEntity(
        world.files,
        event.payload.fileId,
        "File",
      );

      if (event.payload.deviceId) {
        requireEntity(
          world.devices,
          event.payload.deviceId,
          "Device",
        );
      }

      if (event.payload.accountId) {
        requireEntity(
          world.accounts,
          event.payload.accountId,
          "Account",
        );
      }

      return;

    case "NETWORK_CONNECTION":
    case "ENDPOINT_HEARTBEAT":
      requireEntity(
        world.devices,
        event.payload.deviceId,
        "Device",
      );

      return;

    case "ALERT_CREATED":
      if (
        event.payload.applicationId
      ) {
        requireEntity(
          world.applications,
          event.payload.applicationId,
          "Application",
        );
      }

      return;

    case "EMAIL_RECEIVED":
      requireEntity(
        world.accounts,
        event.payload.accountId,
        "Account",
      );

      return;

    default:
      return assertNever(event);
  }
}
