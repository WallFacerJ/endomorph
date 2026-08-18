import { describe, expect, it } from "vitest";

import {
  exampleAccount,
  exampleApplication,
  exampleDevice,
  exampleFile,
  exampleLoginEvent,
  exampleOrganization,
  exampleSession,
  exampleUser,
} from "./exampleWorld";

describe("example synthetic enterprise", () => {
  it("connects the user to the organization", () => {
    expect(exampleUser.organizationId)
      .toBe(exampleOrganization.id);
  });

  it("connects the account to the user", () => {
    expect(exampleAccount.userId)
      .toBe(exampleUser.id);

    expect(exampleUser.accountIds)
      .toContain(exampleAccount.id);
  });

  it("connects the device to its owner", () => {
    expect(exampleDevice.ownerUserId)
      .toBe(exampleUser.id);

    expect(exampleUser.deviceIds)
      .toContain(exampleDevice.id);
  });

  it("connects the file to the device and user", () => {
    expect(exampleFile.deviceId)
      .toBe(exampleDevice.id);

    expect(exampleFile.ownerUserId)
      .toBe(exampleUser.id);
  });

  it("connects the session to account, device, and application", () => {
    expect(exampleSession.accountId)
      .toBe(exampleAccount.id);

    expect(exampleSession.deviceId)
      .toBe(exampleDevice.id);

    expect(exampleSession.applicationId)
      .toBe(exampleApplication.id);
  });

  it("records the login event against the same world entities", () => {
    expect(exampleLoginEvent.type)
      .toBe("AUTH_LOGIN");

    expect(exampleLoginEvent.actorId)
      .toBe(exampleAccount.id);

    expect(exampleLoginEvent.subjectId)
      .toBe(exampleUser.id);

    expect(exampleLoginEvent.payload.deviceId)
      .toBe(exampleDevice.id);
  });
});