import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  AccountDisabledEvent,
} from "./simulationEvent";

import {
  InMemoryEventBus,
} from "./eventBus";

function createEvent(
  id: string,
  timestamp: string,
): AccountDisabledEvent {
  return {
    id,
    type: "ACCOUNT_DISABLED",
    timestamp,
    source: "identity",
    payload: {
      accountId: "account-001",
    },
  };
}

describe("InMemoryEventBus", () => {
  it("stores and delivers published events exactly once in order", () => {
    const bus =
      new InMemoryEventBus();

    const received: string[] = [];

    bus.subscribe((event) => {
      received.push(event.id);
    });

    const first = createEvent(
      "event-001",
      "2026-08-20T09:00:00Z",
    );

    const second = createEvent(
      "event-002",
      "2026-08-20T09:01:00Z",
    );

    bus.publish(first);
    bus.publish(second);

    expect(bus.size)
      .toBe(2);

    expect(bus.all())
      .toEqual([
        first,
        second,
      ]);

    expect(received)
      .toEqual([
        "event-001",
        "event-002",
      ]);
  });

  it("delivers to subscribers in registration order", () => {
    const bus =
      new InMemoryEventBus();

    const calls: string[] = [];

    bus.subscribe(() => {
      calls.push("first");
    });

    bus.subscribe(() => {
      calls.push("second");
    });

    bus.publish(
      createEvent(
        "event-001",
        "2026-08-20T09:00:00Z",
      ),
    );

    expect(calls)
      .toEqual([
        "first",
        "second",
      ]);
  });

  it("stops delivering to unsubscribed handlers", () => {
    const bus =
      new InMemoryEventBus();

    const received: string[] = [];

    const unsubscribe =
      bus.subscribe((event) => {
        received.push(event.id);
      });

    bus.publish(
      createEvent(
        "event-001",
        "2026-08-20T09:00:00Z",
      ),
    );

    unsubscribe();
    unsubscribe();

    bus.publish(
      createEvent(
        "event-002",
        "2026-08-20T09:01:00Z",
      ),
    );

    expect(received)
      .toEqual([
        "event-001",
      ]);
  });

  it("allows independent subscribers to observe the same event", () => {
    const bus =
      new InMemoryEventBus();

    const first: string[] = [];
    const second: string[] = [];

    bus.subscribe((event) => {
      first.push(event.id);
    });

    bus.subscribe((event) => {
      second.push(event.id);
    });

    bus.publish(
      createEvent(
        "event-001",
        "2026-08-20T09:00:00Z",
      ),
    );

    expect(first)
      .toEqual(["event-001"]);

    expect(second)
      .toEqual(["event-001"]);
  });
});
