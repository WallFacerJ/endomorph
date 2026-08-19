import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
  exampleUser,
} from "@polymorph/domain";

import type {
  AccountDisabledEvent,
} from "./simulationEvent";

import {
  InMemoryEventStore,
} from "./eventStore";

function createEvent(
  id: string,
  timestamp: string,
): AccountDisabledEvent {
  return {
    id,

    type: "ACCOUNT_DISABLED",

    timestamp,

    source: "identity",

    actorId:
      exampleUser.id,

    subjectId:
      exampleAccount.id,

    payload: {
      accountId:
        exampleAccount.id,
    },
  };
}

describe("InMemoryEventStore", () => {
  it("appends events in order", () => {
    const store =
      new InMemoryEventStore();

    const first = createEvent(
      "event-001",
      "2026-08-18T09:10:00Z",
    );

    const second = createEvent(
      "event-002",
      "2026-08-18T09:20:00Z",
    );

    store.append(first);
    store.append(second);

    expect(store.size)
      .toBe(2);

    expect(store.all())
      .toEqual([
        first,
        second,
      ]);
  });

  it("accepts events with identical timestamps", () => {
    const store =
      new InMemoryEventStore();

    store.append(
      createEvent(
        "event-001",
        "2026-08-18T09:10:00Z",
      ),
    );

    store.append(
      createEvent(
        "event-002",
        "2026-08-18T09:10:00Z",
      ),
    );

    expect(store.size)
      .toBe(2);
  });

  it("rejects duplicate event ids", () => {
    const store =
      new InMemoryEventStore();

    const event = createEvent(
      "event-001",
      "2026-08-18T09:10:00Z",
    );

    store.append(event);

    expect(
      () => store.append(event),
    ).toThrow(
      "Duplicate event id: event-001",
    );
  });

  it("rejects events appended out of chronological order", () => {
    const store =
      new InMemoryEventStore();

    store.append(
      createEvent(
        "event-later",
        "2026-08-18T09:30:00Z",
      ),
    );

    expect(
      () =>
        store.append(
          createEvent(
            "event-earlier",
            "2026-08-18T09:15:00Z",
          ),
        ),
    ).toThrow(
      "Events must be appended in chronological order.",
    );
  });

  it("returns a copy instead of exposing its internal event array", () => {
    const store =
      new InMemoryEventStore();

    store.append(
      createEvent(
        "event-001",
        "2026-08-18T09:10:00Z",
      ),
    );

    const returned =
      store.all() as
        AccountDisabledEvent[];

    returned.pop();

    expect(store.size)
      .toBe(1);

    expect(store.all())
      .toHaveLength(1);
  });
});
