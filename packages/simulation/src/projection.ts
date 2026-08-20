import type {
  SimulationEvent,
} from "./simulationEvent";

export interface Projection<
  TState,
  TEvent = SimulationEvent,
> {
  createInitialState: () => TState;

  reduce: (
    state: TState,
    event: TEvent,
  ) => TState;
}

export function rebuildProjection<
  TState,
  TEvent,
>(
  projection: Projection<
    TState,
    TEvent
  >,
  events: readonly TEvent[],
): TState {
  return events.reduce(
    (
      state,
      event,
    ) =>
      projection.reduce(
        state,
        event,
      ),

    projection.createInitialState(),
  );
}

export class LiveProjection<
  TState,
  TEvent = SimulationEvent,
> {
  private currentState: TState;

  constructor(
    private readonly projection:
      Projection<TState, TEvent>,
  ) {
    this.currentState =
      projection.createInitialState();
  }

  get state(): TState {
    return this.currentState;
  }

  apply(event: TEvent): void {
    this.currentState =
      this.projection.reduce(
        this.currentState,
        event,
      );
  }
}
