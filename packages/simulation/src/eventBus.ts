import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  InMemoryEventStore,
} from "./eventStore";

export type EventSubscriber = (
  event: SimulationEvent,
) => void;

export type Unsubscribe = () => void;

export class InMemoryEventBus {
  private readonly subscribers:
    EventSubscriber[] = [];

  constructor(
    private readonly eventStore =
      new InMemoryEventStore(),
  ) {}

  get size(): number {
    return this.eventStore.size;
  }

  publish(
    event: SimulationEvent,
  ): void {
    this.eventStore.append(event);

    for (
      const subscriber of [
        ...this.subscribers,
      ]
    ) {
      subscriber(event);
    }
  }

  subscribe(
    subscriber: EventSubscriber,
  ): Unsubscribe {
    this.subscribers.push(
      subscriber,
    );

    let subscribed = true;

    return () => {
      if (!subscribed) {
        return;
      }

      subscribed = false;

      const index =
        this.subscribers.indexOf(
          subscriber,
        );

      if (index >= 0) {
        this.subscribers.splice(
          index,
          1,
        );
      }
    };
  }

  all():
    readonly SimulationEvent[] {
    return this.eventStore.all();
  }
}
