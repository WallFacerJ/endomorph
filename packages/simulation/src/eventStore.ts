import type {
  SimulationEvent,
} from "./simulationEvent";

export class InMemoryEventStore {
  private readonly events:
    SimulationEvent[] = [];

  private readonly eventIds =
    new Set<string>();

  constructor(
    initialEvents:
      readonly SimulationEvent[] = [],
  ) {
    for (
      const event of initialEvents
    ) {
      this.append(event);
    }
  }

  get size(): number {
    return this.events.length;
  }

  append(
    event: SimulationEvent,
  ): void {
    const timestamp =
      Date.parse(event.timestamp);

    if (!Number.isFinite(timestamp)) {
      throw new Error(
        `Invalid event timestamp: ${event.timestamp}`,
      );
    }

    if (
      this.eventIds.has(event.id)
    ) {
      throw new Error(
        `Duplicate event id: ${event.id}`,
      );
    }

    const previousEvent =
      this.events[
        this.events.length - 1
      ];

    if (previousEvent) {
      const previousTimestamp =
        Date.parse(
          previousEvent.timestamp,
        );

      if (
        timestamp <
        previousTimestamp
      ) {
        throw new Error(
          "Events must be appended in chronological order.",
        );
      }
    }

    this.events.push(event);
    this.eventIds.add(event.id);
  }

  all():
    readonly SimulationEvent[] {
    return [...this.events];
  }
}
