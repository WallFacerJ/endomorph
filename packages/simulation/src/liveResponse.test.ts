import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  runLiveResponse,
} from "./liveResponse";

const DEVICE = "device-001";

const OTHER_DEVICE = "device-002";

function heartbeat(
  id: string,
  timestamp: string,
  status:
    | "active"
    | "inactive" = "active",
  deviceId: string = DEVICE,
): SimulationEvent {
  return {
    id,
    type: "ENDPOINT_HEARTBEAT",
    timestamp,
    source: "endpoint-agent",
    subjectId: deviceId,
    payload: {
      deviceId,
      status,
      ipAddresses: ["10.0.0.5"],
    },
  };
}

function process(
  id: string,
  timestamp: string,
  image: string,
  processId: string,
  deviceId: string = DEVICE,
): SimulationEvent {
  return {
    id,
    type: "PROCESS_STARTED",
    timestamp,
    source: "edr",
    subjectId: deviceId,
    payload: {
      deviceId,
      processId,
      image,
      commandLine: `${image} --run`,
    },
  };
}

function connection(
  id: string,
  timestamp: string,
  processId: string | undefined,
  image: string | undefined,
  destinationIp = "203.0.113.9",
): SimulationEvent {
  return {
    id,
    type: "NETWORK_CONNECTION",
    timestamp,
    source: "network",
    subjectId: DEVICE,
    payload: {
      deviceId: DEVICE,
      protocol: "tcp",
      sourceIp: "10.0.0.5",
      destinationIp,
      destinationPort: 443,
      ...(processId ? { processId } : {}),
      ...(image ? { image } : {}),
    },
  };
}

const NOW = "2026-08-20T12:00:00.000Z";

describe("runLiveResponse", () => {
  describe("host reachability", () => {
    it("says a contained host is still reachable, because it is", () => {
      /*
        The misconception this exists to correct. Analysts routinely believe
        isolating a machine cuts them off from it, and hesitate over
        containment for that reason. It does the opposite: the agent channel
        is what survives, which is the entire point of containment.
      */
      const result = runLiveResponse({
        command: "processes",
        deviceId: DEVICE,
        now: NOW,
        events: [
          heartbeat(
            "hb-1",
            "2026-08-20T11:00:00.000Z",
          ),
          process(
            "p-1",
            "2026-08-20T11:30:00.000Z",
            "C:\\Windows\\notepad.exe",
            "1000",
          ),
          heartbeat(
            "hb-2",
            "2026-08-20T11:50:00.000Z",
            "inactive",
          ),
        ],
      });

      expect(
        result.host.reachability,
      ).toBe("contained");

      expect(
        result.host.reachabilityBasis,
      ).toContain("retained");

      // Reachable means results, not an empty screen.
      expect(
        result.rows.length,
      ).toBeGreaterThan(0);
    });

    it("returns nothing for a host that has never checked in, and says why", () => {
      /*
        Showing history for a machine that is not answering would be the worst
        thing this console could do: it would read as live state for a host
        that may have been rebuilt hours ago.
      */
      const result = runLiveResponse({
        command: "processes",
        deviceId: DEVICE,
        now: NOW,
        events: [
          process(
            "p-1",
            "2026-08-20T11:30:00.000Z",
            "C:\\Windows\\notepad.exe",
            "1000",
          ),
        ],
      });

      expect(
        result.host.reachability,
      ).toBe("not-reporting");

      expect(result.rows).toEqual([]);

      expect(
        result.host.reachabilityBasis,
      ).toContain("silent");
    });
  });

  describe("process state", () => {
    const events: SimulationEvent[] = [
      heartbeat(
        "hb-1",
        "2026-08-20T11:00:00.000Z",
      ),

      // Recent attributed traffic: still running.
      process(
        "p-live",
        "2026-08-20T11:10:00.000Z",
        "C:\\Windows\\powershell.exe",
        "7734",
      ),
      connection(
        "c-live",
        "2026-08-20T11:55:00.000Z",
        "7734",
        "C:\\Windows\\powershell.exe",
      ),

      // A utility that does one thing and returns.
      process(
        "p-oneshot",
        "2026-08-20T11:20:00.000Z",
        "C:\\Windows\\System32\\whoami.exe",
        "2200",
      ),

      // Nothing attributed after it started.
      process(
        "p-silent",
        "2026-08-20T11:30:00.000Z",
        "C:\\Windows\\mystery.exe",
        "3300",
      ),
    ];

    function stateOf(image: string) {
      const result = runLiveResponse({
        command: "processes",
        deviceId: DEVICE,
        now: NOW,
        events,
      });

      return result.rows.find(
        (row) => row.primary === image,
      );
    }

    it("calls a process running when something was attributed to it recently", () => {
      const row = stateOf(
        "powershell.exe",
      );

      expect(row?.state).toBe("running");

      expect(row?.basis).toContain(
        "attributed",
      );
    });

    it("calls a one-shot utility exited", () => {
      expect(
        stateOf("whoami.exe")?.state,
      ).toBe("exited");
    });

    it("refuses to guess about anything else", () => {
      /*
        The honest answer, and the one worth teaching. "Probably still
        running" is the sort of confident wrong answer that costs an analyst
        an afternoon, and real live response has exactly this gap when the
        sensor does not record process exit.
      */
      const row = stateOf("mystery.exe");

      expect(row?.state).toBe("unknown");

      expect(row?.basis).toContain(
        "cannot be read",
      );
    });

    it("puts what is running above what is not", () => {
      const result = runLiveResponse({
        command: "processes",
        deviceId: DEVICE,
        now: NOW,
        events,
      });

      expect(result.rows[0]?.state).toBe(
        "running",
      );
    });

    it("gives every row a reason, never a bare verdict", () => {
      // A state with no reasoning attached is an assertion, and an analyst
      // who cannot see how a verdict was reached learns to accept verdicts.
      const result = runLiveResponse({
        command: "processes",
        deviceId: DEVICE,
        now: NOW,
        events,
      });

      for (const row of result.rows) {
        expect(row.state).toBeDefined();
        expect(row.basis).toBeTruthy();
      }
    });
  });

  it("cannot see past the clock it was given", () => {
    /*
      The console reads the replayed window, so rewinding and re-running a
      command has to show what the host would have said then. A view that
      leaked later events would make "was the persistence there yet when the
      alert fired" unanswerable, and answer it wrongly rather than refusing.
    */
    const events: SimulationEvent[] = [
      heartbeat(
        "hb-1",
        "2026-08-20T11:00:00.000Z",
      ),
      process(
        "p-early",
        "2026-08-20T11:10:00.000Z",
        "C:\\Windows\\early.exe",
        "1000",
      ),
      process(
        "p-late",
        "2026-08-20T13:00:00.000Z",
        "C:\\Windows\\late.exe",
        "2000",
      ),
    ];

    const result = runLiveResponse({
      command: "processes",
      deviceId: DEVICE,
      now: NOW,
      events,
    });

    const names = result.rows.map(
      (row) => row.primary,
    );

    expect(names).toContain("early.exe");

    expect(names).not.toContain(
      "late.exe",
    );
  });

  it("answers only for the host that was asked", () => {
    const result = runLiveResponse({
      command: "processes",
      deviceId: DEVICE,
      now: NOW,
      events: [
        heartbeat(
          "hb-1",
          "2026-08-20T11:00:00.000Z",
        ),
        process(
          "p-mine",
          "2026-08-20T11:10:00.000Z",
          "C:\\Windows\\mine.exe",
          "1000",
        ),
        process(
          "p-theirs",
          "2026-08-20T11:20:00.000Z",
          "C:\\Windows\\theirs.exe",
          "2000",
          OTHER_DEVICE,
        ),
      ],
    });

    expect(
      result.rows.map(
        (row) => row.primary,
      ),
    ).toEqual(["mine.exe"]);
  });

  describe("connections", () => {
    it("groups repeated traffic and names the program responsible", () => {
      const result = runLiveResponse({
        command: "connections",
        deviceId: DEVICE,
        now: NOW,
        events: [
          heartbeat(
            "hb-1",
            "2026-08-20T11:00:00.000Z",
          ),
          connection(
            "c-1",
            "2026-08-20T11:10:00.000Z",
            "7734",
            "C:\\Windows\\powershell.exe",
          ),
          connection(
            "c-2",
            "2026-08-20T11:15:00.000Z",
            "7734",
            "C:\\Windows\\powershell.exe",
          ),
          connection(
            "c-3",
            "2026-08-20T11:20:00.000Z",
            "4400",
            "C:\\Office\\OUTLOOK.EXE",
            "203.0.113.50",
          ),
        ],
      });

      expect(result.rows).toHaveLength(2);

      const beacon = result.rows.find(
        (row) =>
          row.primary ===
          "203.0.113.9:443",
      );

      // Count and program on the row, because they are the two fields that
      // separate one destination from another at a glance.
      expect(beacon?.secondary).toBe(
        "2 connections · powershell.exe",
      );
    });

    it("says so when a connection has no process behind it", () => {
      /*
        A network sensor off the host sees the packet and not the program.
        Saying "not attributed" is different from saying nothing, and the
        difference matters when an analyst is deciding whether the absence is
        evidence.
      */
      const result = runLiveResponse({
        command: "connections",
        deviceId: DEVICE,
        now: NOW,
        events: [
          heartbeat(
            "hb-1",
            "2026-08-20T11:00:00.000Z",
          ),
          connection(
            "c-1",
            "2026-08-20T11:10:00.000Z",
            undefined,
            undefined,
          ),
        ],
      });

      expect(
        result.rows[0]?.secondary,
      ).toContain("not attributed");
    });
  });

  it("carries what the view cannot tell you, on every command", () => {
    for (const command of [
      "processes",
      "connections",
      "persistence",
      "logons",
      "files",
    ] as const) {
      const result = runLiveResponse({
        command,
        deviceId: DEVICE,
        now: NOW,
        events: [
          heartbeat(
            "hb-1",
            "2026-08-20T11:00:00.000Z",
          ),
        ],
      });

      expect(
        result.limitation.length,
      ).toBeGreaterThan(40);
    }
  });
});
