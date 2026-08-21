import {
  describe,
  expect,
  it,
} from "vitest";

import {
  createWorldState,
  validateSimulationEvent,
} from "@endomorph/simulation";

import {
  DEFAULT_ACTIVITY_OPTIONS,
  generateBackgroundActivity,
} from "./backgroundActivity.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

const enterprise = generateEnterprise();

const activity =
  generateBackgroundActivity(enterprise);

function worldFor(
  source: typeof enterprise,
) {
  return createWorldState({
    simulationTime:
      source.profile.startTime,
    organizations: source.organizations,
    users: source.users,
    accounts: source.accounts,
    devices: source.devices,
    files: source.files,
    applications: source.applications,
  });
}

describe("generateBackgroundActivity", () => {
  describe("determinism", () => {
    it("produces identical activity from the same seed", () => {
      expect(
        generateBackgroundActivity(
          generateEnterprise({
            seed: 555,
          }),
        ),
      ).toEqual(
        generateBackgroundActivity(
          generateEnterprise({
            seed: 555,
          }),
        ),
      );
    });

    it("produces different activity from a different seed", () => {
      expect(
        generateBackgroundActivity(
          generateEnterprise({
            seed: 555,
          }),
        ).map((event) => event.type),
      ).not.toEqual(
        generateBackgroundActivity(
          generateEnterprise({
            seed: 777,
          }),
        ).map((event) => event.type),
      );
    });

    it("rejects invalid options", () => {
      expect(() =>
        generateBackgroundActivity(
          enterprise,
          { durationHours: 0 },
        ),
      ).toThrow();

      expect(() =>
        generateBackgroundActivity(
          enterprise,
          {
            heartbeatIntervalMinutes: 0,
          },
        ),
      ).toThrow();
    });
  });

  describe("coherence with the runtime", () => {
    it("passes the simulation's own event validation", () => {
      // The strongest guarantee available: every generated event is legal
      // against the generated world according to the existing runtime, not
      // according to a rule this package invented.
      const world = worldFor(enterprise);

      for (const event of activity) {
        expect(() =>
          validateSimulationEvent(
            world,
            event,
          ),
        ).not.toThrow();
      }
    });

    it("references only entities that exist", () => {
      const known = new Set([
        ...enterprise.users.map(
          (user) => user.id,
        ),
        ...enterprise.accounts.map(
          (account) => account.id,
        ),
        ...enterprise.devices.map(
          (device) => device.id,
        ),
        ...enterprise.applications.map(
          (application) =>
            application.id,
        ),
        ...enterprise.files.map(
          (file) => file.id,
        ),
      ]);

      for (const event of activity) {
        if (event.actorId) {
          expect(
            known.has(event.actorId),
          ).toBe(true);
        }
      }
    });
  });

  describe("ordering and identity", () => {
    it("returns events in chronological order", () => {
      for (
        let index = 1;
        index < activity.length;
        index += 1
      ) {
        expect(
          activity[index].timestamp >=
            activity[index - 1]
              .timestamp,
        ).toBe(true);
      }
    });

    it("assigns a unique id to every event", () => {
      const ids = activity.map(
        (event) => event.id,
      );

      expect(new Set(ids).size).toBe(
        ids.length,
      );
    });

    it("keeps every event inside the generated history window", () => {
      const start = Date.parse(
        enterprise.profile.startTime,
      );

      const end =
        start +
        DEFAULT_ACTIVITY_OPTIONS.days *
          24 *
          60 *
          60 *
          1000;

      for (const event of activity) {
        const at = Date.parse(
          event.timestamp,
        );

        expect(
          at,
        ).toBeGreaterThanOrEqual(start);

        expect(at).toBeLessThan(end);
      }
    });
  });

  describe("multi-day baseline", () => {
    // The point of history is that it makes an observation anomalous.
    // "This account signed in from an address it has never used" is
    // unanswerable against one day. These assert the baseline is real.
    const successfulLogins =
      activity.filter(
        (event) =>
          event.type ===
          "AUTH_LOGIN_SUCCEEDED",
      );

    function loginsFor(userId: string) {
      return successfulLogins.filter(
        (event) =>
          event.type ===
            "AUTH_LOGIN_SUCCEEDED" &&
          event.payload.userId ===
            userId,
      );
    }

    it("spans the configured number of days", () => {
      const days = new Set(
        activity.map((event) =>
          event.timestamp.slice(0, 10),
        ),
      );

      expect(days.size).toBe(
        DEFAULT_ACTIVITY_OPTIONS.days,
      );
    });

    it("quietens down at the weekend", () => {
      const perDay = new Map<
        string,
        number
      >();

      for (const event of activity) {
        const day =
          event.timestamp.slice(0, 10);

        perDay.set(
          day,
          (perDay.get(day) ?? 0) + 1,
        );
      }

      const counts = [
        ...perDay.entries(),
      ].map(([day, count]) => ({
        weekend: [0, 6].includes(
          new Date(
            `${day}T12:00:00.000Z`,
          ).getUTCDay(),
        ),
        count,
      }));

      const weekdayMin = Math.min(
        ...counts
          .filter((c) => !c.weekend)
          .map((c) => c.count),
      );

      const weekendMax = Math.max(
        ...counts
          .filter((c) => c.weekend)
          .map((c) => c.count),
      );

      expect(weekendMax).toBeLessThan(
        weekdayMin,
      );
    });

    it("keeps each person on a stable source address", () => {
      // A staff member works from their own workstation every day. This is
      // precisely what makes the incident's foreign address stand out.
      const workers =
        enterprise.users.filter(
          (user) =>
            user.status === "active" &&
            loginsFor(user.id).length >=
              4,
        );

      expect(
        workers.length,
      ).toBeGreaterThan(20);

      for (const user of workers) {
        const addresses = new Set(
          loginsFor(user.id).map(
            (event) =>
              event.type ===
              "AUTH_LOGIN_SUCCEEDED"
                ? event.payload.sourceIp
                : undefined,
          ),
        );

        expect(addresses.size).toBe(1);
      }
    });

    it("keeps each person on a habitual subset of applications", () => {
      const workers =
        enterprise.users.filter(
          (user) =>
            loginsFor(user.id).length >=
            6,
        );

      expect(
        workers.length,
      ).toBeGreaterThan(10);

      for (const user of workers) {
        const applications = new Set(
          loginsFor(user.id).map(
            (event) =>
              event.type ===
              "AUTH_LOGIN_SUCCEEDED"
                ? event.payload
                    .applicationId
                : undefined,
          ),
        );

        // Habitual, not exhaustive: nobody touches the whole estate.
        expect(
          applications.size,
        ).toBeLessThan(
          enterprise.applications.length,
        );
      }
    });

    it("keeps arrival times recognisable across days", () => {
      const user = enterprise.users.find(
        (candidate) =>
          candidate.status === "active",
      );

      const arrivals = activity
        .filter(
          (event) =>
            event.type ===
              "SESSION_STARTED" &&
            event.actorId?.startsWith(
              "account-",
            ) &&
            event.subjectId?.includes(
              user?.id ?? "__none__",
            ),
        )
        .map((event) =>
          Number(
            event.timestamp.slice(11, 13),
          ),
        );

      expect(
        arrivals.length,
      ).toBeGreaterThan(1);

      // Same person, same rough hour each day.
      expect(
        Math.max(...arrivals) -
          Math.min(...arrivals),
      ).toBeLessThanOrEqual(2);
    });

    it("gives each day its own session identity", () => {
      const sessions = new Set(
        activity
          .filter(
            (event) =>
              event.type ===
              "SESSION_STARTED",
          )
          .map(
            (event) => event.subjectId,
          ),
      );

      // One shared session id across five days would make session analysis
      // meaningless.
      expect(
        sessions.size,
      ).toBeGreaterThan(
        enterprise.users.length,
      );
    });

    it("scales volume with the number of days", () => {
      const oneDay =
        generateBackgroundActivity(
          enterprise,
          { days: 1 },
        );

      expect(
        activity.length,
      ).toBeGreaterThan(oneDay.length);
    });

    it("rejects a non-positive day count", () => {
      expect(() =>
        generateBackgroundActivity(
          enterprise,
          { days: 0 },
        ),
      ).toThrow();

      expect(() =>
        generateBackgroundActivity(
          enterprise,
          { days: 1.5 },
        ),
      ).toThrow();
    });
  });

  describe("noise quality", () => {
    it("generates a volume an analyst cannot scroll", () => {
      // The v1 scenarios shipped 6 and 34 opening events. Phase 1 requires
      // a dataset that has to be searched.
      expect(
        activity.length,
      ).toBeGreaterThan(3000);
    });

    it("covers every telemetry family the Ops tools project", () => {
      const types = new Set(
        activity.map(
          (event) => event.type,
        ),
      );

      for (const expected of [
        "ENDPOINT_HEARTBEAT",
        "AUTH_LOGIN_SUCCEEDED",
        "AUTH_LOGIN_FAILED",
        "SESSION_STARTED",
        "PROCESS_STARTED",
        "NETWORK_CONNECTION",
        "FILE_ACCESSED",
      ]) {
        expect(
          types.has(expected as never),
        ).toBe(true);
      }
    });

    it("produces benign authentication failures to rule out", () => {
      const failures = activity.filter(
        (event) =>
          event.type ===
          "AUTH_LOGIN_FAILED",
      );

      expect(
        failures.length,
      ).toBeGreaterThan(5);

      // Benign noise must not drown the signal a real incident will add.
      expect(
        failures.length /
          activity.length,
      ).toBeLessThan(0.05);
    });

    it("peaks during the morning arrival window", () => {
      const hourly = new Map<
        string,
        number
      >();

      for (const event of activity) {
        const hour =
          event.timestamp.slice(11, 13);

        hourly.set(
          hour,
          (hourly.get(hour) ?? 0) + 1,
        );
      }

      const busiest = [
        ...hourly.entries(),
      ].sort(
        (left, right) =>
          right[1] - left[1],
      )[0][0];

      expect(["09", "10"]).toContain(
        busiest,
      );
    });

    it("matches process images to each host operating system", () => {
      const devicesById = new Map(
        enterprise.devices.map(
          (device) => [
            device.id,
            device,
          ],
        ),
      );

      for (const event of activity) {
        if (
          event.type !==
          "PROCESS_STARTED"
        ) {
          continue;
        }

        const device = devicesById.get(
          event.payload.deviceId,
        );

        if (
          device?.operatingSystem.startsWith(
            "Windows",
          )
        ) {
          expect(
            event.payload.image,
          ).toMatch(/^[A-Z]:\\/);
        } else {
          expect(
            event.payload.image,
          ).toMatch(/^\//);
        }
      }
    });

    it("mixes internal and external network destinations", () => {
      const connections =
        activity.filter(
          (event) =>
            event.type ===
            "NETWORK_CONNECTION",
        );

      const internal =
        connections.filter((event) =>
          event.type ===
          "NETWORK_CONNECTION"
            ? event.payload.destinationIp.startsWith(
                "10.",
              )
            : false,
        );

      expect(
        internal.length,
      ).toBeGreaterThan(0);

      expect(
        connections.length -
          internal.length,
      ).toBeGreaterThan(0);
    });

    it("does not sign dormant or disabled staff into applications", () => {
      const inactiveUserIds = new Set(
        enterprise.users
          .filter(
            (user) =>
              user.status !== "active",
          )
          .map((user) => user.id),
      );

      for (const event of activity) {
        if (
          event.type ===
          "AUTH_LOGIN_SUCCEEDED"
        ) {
          expect(
            inactiveUserIds.has(
              event.payload.userId,
            ),
          ).toBe(false);
        }
      }
    });

    it("scales with the configured day length", () => {
      const shortDay =
        generateBackgroundActivity(
          enterprise,
          { durationHours: 2 },
        );

      expect(
        shortDay.length,
      ).toBeLessThan(activity.length);
    });
  });
});
