import type {
  SimulationTimestamp,
} from "@polymorph/domain";

export class VirtualClock {
  private currentMilliseconds: number;

  constructor(
    initialTime: SimulationTimestamp,
  ) {
    const parsed =
      Date.parse(initialTime);

    if (!Number.isFinite(parsed)) {
      throw new Error(
        `Invalid simulation timestamp: ${initialTime}`,
      );
    }

    this.currentMilliseconds = parsed;
  }

  now(): SimulationTimestamp {
    return new Date(
      this.currentMilliseconds,
    ).toISOString();
  }

  advanceMilliseconds(
    milliseconds: number,
  ): SimulationTimestamp {
    if (
      !Number.isFinite(milliseconds) ||
      milliseconds < 0
    ) {
      throw new Error(
        "Clock advancement must be a non-negative finite number.",
      );
    }

    this.currentMilliseconds +=
      milliseconds;

    return this.now();
  }

  advanceSeconds(
    seconds: number,
  ): SimulationTimestamp {
    return this.advanceMilliseconds(
      seconds * 1000,
    );
  }

  advanceMinutes(
    minutes: number,
  ): SimulationTimestamp {
    return this.advanceSeconds(
      minutes * 60,
    );
  }
}
