import type {
  AutorunEntry,
  EntityId,
  SimulationTimestamp,
} from "@endomorph/domain";

import type {
  SimulationEvent,
} from "./simulationEvent";

/**
 * What is true on this host right now.
 *
 * Every other console in this product answers a historical question: what did
 * this host do? A responder deciding whether to pull a machine off the
 * network has a different one, and asks it of the machine rather than of the
 * log -- is that process still running, is the persistence still installed,
 * who is signed in at this moment.
 *
 * The distinction matters because the two questions have different answers.
 * Telemetry says a run key was written at 14:02. Live response says it is
 * still there at 16:40, and that is what decides whether the machine can go
 * back to its owner.
 *
 * Three constraints shaped this.
 *
 * It invents nothing. Every fact below is derived from events already in the
 * corpus and already visible in the endpoint console; what changes is the
 * framing, from "happened at some point" to "true as of now". A live-response
 * view that knew things the telemetry did not would be handing over the
 * answer, and an analyst would learn to run it first and think second.
 *
 * It says when it does not know. This sensor records process start and not
 * process exit, so for many processes the honest answer is that the corpus
 * cannot say -- and real live response has exactly these gaps. Three states,
 * one of them "unknown", each carrying the reason, teaches the job better
 * than two states and a guess.
 *
 * It runs against any host in the estate, deliberately. Running the same
 * command on a machine you suspect and a machine you do not is how an analyst
 * learns what ordinary looks like, and not knowing that is the largest single
 * gap in people new to the work.
 */

export type LiveResponseCommandId =
  | "processes"
  | "connections"
  | "persistence"
  | "logons"
  | "files";

export type ProcessLiveState =
  | "running"
  | "exited"
  | "unknown";

export type HostReachability =
  | "online"
  | "contained"
  | "not-reporting";

export interface LiveResponseHost {
  readonly deviceId: EntityId;

  readonly reachability: HostReachability;

  /** Why the host is in that state, in the responder's terms. */
  readonly reachabilityBasis: string;

  readonly lastCheckIn:
    | SimulationTimestamp
    | undefined;
}

export interface LiveResponseRow {
  readonly primary: string;

  readonly secondary: string | undefined;

  readonly detail: string | undefined;

  /** Only meaningful for the process listing. */
  readonly state:
    | ProcessLiveState
    | undefined;

  /** Why this row says what it says. Never omitted where a state is given. */
  readonly basis: string | undefined;

  /** Lets a row be collected as evidence like any other observation. */
  readonly eventId: EntityId | undefined;

  /**
   * Where the row came from.
   *
   * "baseline" is host state that predates the window -- there is no event
   * behind it and nothing to collect. "observed" was seen being established
   * while the sensor was watching.
   */
  readonly origin: "baseline" | "observed";

  /** Absent for baseline state, which was configured before any of this. */
  readonly timestamp:
    | SimulationTimestamp
    | undefined;
}

export interface LiveResponseResult {
  readonly command: LiveResponseCommandId;

  readonly host: LiveResponseHost;

  readonly rows: readonly LiveResponseRow[];

  /**
   * What this view cannot tell you.
   *
   * Carried with every result rather than written once in documentation,
   * because the moment a responder needs to know the limits of a view is
   * while they are reading it.
   */
  readonly limitation: string;
}

export interface LiveResponseRequest {
  readonly command: LiveResponseCommandId;

  readonly deviceId: EntityId;

  /** The virtual clock's now. Nothing after this is visible. */
  readonly now: SimulationTimestamp;

  readonly events: readonly SimulationEvent[];

  /**
   * What the host is configured to start, as world state.
   *
   * Passed in rather than derived, because it is not telemetry: most of a
   * machine's autoruns were configured long before any sensor was watching,
   * and a listing that showed only what was installed during the window would
   * make the intrusion's entry the only row on the screen.
   */
  readonly autoruns?: readonly AutorunEntry[];
}

/**
 * How recently a process must have been seen doing something to be called
 * running.
 *
 * This is an inference, not a fact, and the row says so. Fifteen minutes is
 * long enough to cover a beacon at a five-minute interval, and short enough
 * that a process which stopped is not reported as live for the rest of the
 * shift.
 */
const ACTIVE_WINDOW_MINUTES = 15;

/**
 * How far back the process listing looks.
 *
 * A real listing shows what is resident now. Without an exit event the
 * closest honest equivalent is a recent window, and reporting three days of
 * process starts as "unknown" would bury the few rows that matter.
 */
const PROCESS_LOOKBACK_HOURS = 24;

/**
 * Programs that do one thing and exit.
 *
 * A genuine property of these binaries rather than a guess about a particular
 * incident: they print or change something and return. Anything not listed is
 * reported unknown, because "probably still running" is the sort of confident
 * wrong answer that costs an analyst an afternoon.
 */
const ONE_SHOT_IMAGES: readonly string[] =
  [
    "whoami.exe",
    "net.exe",
    "net1.exe",
    "ipconfig.exe",
    "arp.exe",
    "nltest.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "quser.exe",
    "reg.exe",
    "hostname",
    "id",
    "uname",
    "systemctl",
    "launchctl",
  ];

/**
 * Newest first, with undated rows last.
 *
 * Baseline host state has no timestamp -- it was configured before the window
 * opened -- and sorting it as if it were epoch zero would bury it or float it
 * depending on the direction, neither of which means anything.
 */
function newestFirst(
  left: { timestamp: string | undefined },
  right: { timestamp: string | undefined },
): number {
  if (!left.timestamp) {
    return right.timestamp ? 1 : 0;
  }

  if (!right.timestamp) {
    return -1;
  }

  return (
    Date.parse(right.timestamp) -
    Date.parse(left.timestamp)
  );
}

function basename(path: string): string {
  const segments = path.split(/[\\/]/);

  return (
    segments[segments.length - 1] ?? path
  );
}

function minutesBetween(
  earlier: SimulationTimestamp,
  later: SimulationTimestamp,
): number {
  return (
    (Date.parse(later) -
      Date.parse(earlier)) /
    60000
  );
}

function describeAge(
  minutes: number,
): string {
  if (minutes < 1) {
    return "less than a minute ago";
  }

  if (minutes < 90) {
    return `${Math.round(minutes)} minutes ago`;
  }

  return `${Math.round(minutes / 60)} hours ago`;
}

function isOneShot(image: string): boolean {
  const name = basename(
    image,
  ).toLowerCase();

  return ONE_SHOT_IMAGES.some(
    (candidate) => candidate === name,
  );
}

function visibleEvents(
  request: LiveResponseRequest,
): readonly SimulationEvent[] {
  const cutoff = Date.parse(request.now);

  return request.events.filter(
    (event) =>
      Date.parse(event.timestamp) <=
      cutoff,
  );
}

/**
 * Whether the host can be reached, and why.
 *
 * Containment is the case worth getting right. Analysts routinely believe
 * isolating a machine cuts them off from it; it does the opposite, because
 * the entire point of the containment channel is that it survives. Saying so
 * at the moment somebody is deciding whether to isolate is worth more than
 * saying it in a lesson.
 */
function resolveHost(
  deviceId: EntityId,
  events: readonly SimulationEvent[],
): LiveResponseHost {
  const beats = events.filter(
    (event) =>
      event.type ===
        "ENDPOINT_HEARTBEAT" &&
      event.payload.deviceId === deviceId,
  );

  const latest = beats[beats.length - 1];

  if (!latest) {
    return {
      deviceId,
      reachability: "not-reporting",
      reachabilityBasis:
        "No agent check-in has been recorded for this host. Nothing below can be gathered, and the results are empty because the host is silent rather than because it is clean.",
      lastCheckIn: undefined,
    };
  }

  if (
    latest.type === "ENDPOINT_HEARTBEAT" &&
    latest.payload.status !== "active"
  ) {
    return {
      deviceId,
      reachability: "contained",
      reachabilityBasis:
        "The host is contained. The agent channel is retained, which is the point of containment: the machine is cut off from the network, not from you, and live response still works.",
      lastCheckIn: latest.timestamp,
    };
  }

  return {
    deviceId,
    reachability: "online",
    reachabilityBasis:
      "The agent is checking in normally.",
    lastCheckIn: latest.timestamp,
  };
}

function processRows(
  request: LiveResponseRequest,
  events: readonly SimulationEvent[],
): readonly LiveResponseRow[] {
  const horizon =
    Date.parse(request.now) -
    PROCESS_LOOKBACK_HOURS * 3600000;

  /*
    Last time anything was attributed to a pid.

    Built from network activity, because that is the only evidence in the
    corpus that a process was still alive after it started -- which is why
    connections carrying their process matters for more than the network view.
  */
  const lastSeen = new Map<
    string,
    SimulationTimestamp
  >();

  for (const event of events) {
    if (
      event.type !== "NETWORK_CONNECTION" ||
      event.payload.deviceId !==
        request.deviceId ||
      !event.payload.processId
    ) {
      continue;
    }

    lastSeen.set(
      event.payload.processId,
      event.timestamp,
    );
  }

  const rows: LiveResponseRow[] = [];

  for (const event of events) {
    if (
      event.type !== "PROCESS_STARTED" ||
      event.payload.deviceId !==
        request.deviceId ||
      Date.parse(event.timestamp) < horizon
    ) {
      continue;
    }

    const seen = lastSeen.get(
      event.payload.processId,
    );

    const sinceActivity = seen
      ? minutesBetween(seen, request.now)
      : undefined;

    let state: ProcessLiveState =
      "unknown";

    let basis =
      "This sensor records process start and not process exit, and nothing has been attributed to this process since. Whether it is still resident cannot be read from this telemetry.";

    if (
      sinceActivity !== undefined &&
      sinceActivity <=
        ACTIVE_WINDOW_MINUTES
    ) {
      state = "running";
      basis = `Still active: a connection was attributed to this process ${describeAge(
        sinceActivity,
      )}.`;
    } else if (
      isOneShot(event.payload.image)
    ) {
      state = "exited";
      basis =
        "This program does one thing and returns, so it is no longer resident.";
    } else if (
      sinceActivity !== undefined
    ) {
      basis = `Last attributed activity was ${describeAge(
        sinceActivity,
      )}, longer ago than this view treats as live.`;
    }

    rows.push({
      primary: basename(
        event.payload.image,
      ),
      secondary: `pid ${event.payload.processId}`,
      detail:
        event.payload.commandLine ??
        event.payload.image,
      state,
      basis,
      eventId: event.id,
      origin: "observed",
      timestamp: event.timestamp,
    });
  }

  const order: Record<
    ProcessLiveState,
    number
  > = {
    running: 0,
    unknown: 1,
    exited: 2,
  };

  return rows.sort((left, right) => {
    const byState =
      order[left.state ?? "unknown"] -
      order[right.state ?? "unknown"];

    return byState !== 0
      ? byState
      : newestFirst(left, right);
  });
}

function connectionRows(
  request: LiveResponseRequest,
  events: readonly SimulationEvent[],
): readonly LiveResponseRow[] {
  /*
    Grouped by destination and process rather than listed one per line.

    A raw list is unreadable at corpus volume, and it also hides the one thing
    that separates automation from a person: repetition to a single address.
    Grouping surfaces it -- and surfaces it for the mail client too, which is
    the honest version, because that is precisely why beacon detection is
    hard.
  */
  interface ConnectionGroup {
    destination: string;
    port: number | undefined;
    image: string | undefined;
    processId: string | undefined;
    count: number;
    last: SimulationTimestamp;
    eventId: EntityId;
  }

  const groups = new Map<
    string,
    ConnectionGroup
  >();

  for (const event of events) {
    if (
      event.type !== "NETWORK_CONNECTION" ||
      event.payload.deviceId !==
        request.deviceId
    ) {
      continue;
    }

    const key = [
      event.payload.destinationIp,
      event.payload.destinationPort ?? "",
      event.payload.processId ?? "",
    ].join("|");

    const existing = groups.get(key);

    if (existing) {
      existing.count += 1;
      existing.last = event.timestamp;
      continue;
    }

    groups.set(key, {
      destination:
        event.payload.destinationIp,
      port: event.payload.destinationPort,
      image: event.payload.image,
      processId: event.payload.processId,
      count: 1,
      last: event.timestamp,
      eventId: event.id,
    });
  }

  return [...groups.values()]
    .sort(
      (left, right) =>
        Date.parse(right.last) -
        Date.parse(left.last),
    )
    .map((group) => ({
      primary: `${group.destination}:${
        group.port ?? "—"
      }`,

      /*
        Count and program on the row itself.

        Both were behind an expand, which put the two fields that actually
        separate one connection from another out of reach of a scan. Repetition
        is what automation looks like, and the program is what says whether the
        automation is a mail client or somebody else's -- reading a list of
        destinations without them tells an analyst almost nothing.
      */
      secondary: `${group.count} connection${
        group.count === 1 ? "" : "s"
      } · ${
        group.image
          ? basename(group.image)
          : "not attributed"
      }`,

      detail: `Last ${describeAge(
        minutesBetween(
          group.last,
          request.now,
        ),
      )}${
        group.processId
          ? ` · pid ${group.processId}`
          : ""
      }${
        group.image
          ? ` · ${group.image}`
          : ""
      }`,
      state: undefined,
      basis: undefined,
      eventId: group.eventId,
      origin: "observed" as const,
      timestamp: group.last,
    }));
}

/**
 * Parse an autorun out of the command line that created it.
 *
 * The parsing exists so an observed entry can be shown in the same shape as a
 * configured one -- name, location, target. Left as a raw command line it
 * would be the only row on the screen that looked different, and structure
 * alone would mark the intrusion regardless of what it said.
 */
function parseInstall(
  command: string,
): AutorunEntry | undefined {
  const quoted = command.match(/"([^"]+)"/g) ?? [];

  const unquote = (value: string) =>
    value.replace(/^"|"$/g, "");

  if (
    command.includes(
      "CurrentVersion\\Run",
    ) &&
    command.includes(" add ")
  ) {
    const name = command.match(
      /\/v\s+(\S+)/,
    );

    return {
      name: name?.[1] ?? "(unnamed)",
      location: unquote(
        quoted[0] ?? "",
      ),
      target: unquote(
        quoted[quoted.length - 1] ?? "",
      ),
    };
  }

  if (
    command.includes("launchctl load")
  ) {
    const path =
      command.match(/(\S+\.plist)/)?.[1] ??
      "";

    const segments = path.split("/");

    return {
      name:
        segments[segments.length - 1]
          ?.replace(/\.plist$/, "") ?? path,
      location: segments
        .slice(0, -1)
        .join("/"),
      target: path,
    };
  }

  if (
    command.includes("systemctl") &&
    command.includes("enable")
  ) {
    const unit =
      command.match(
        /(\S+\.(?:service|timer))/,
      )?.[1] ?? "";

    return {
      name: unit,
      location: "systemd",
      target: unit,
    };
  }

  return undefined;
}

/**
 * What starts with this machine.
 *
 * Two sources, shown as one list. The host's configured autoruns are world
 * state and make up most of it; entries seen being installed during the
 * window are merged in and marked with when.
 *
 * They are sorted by location and name, the way a real autoruns listing is,
 * and deliberately not by recency. Putting "installed while you were watching"
 * at the top would reduce this to reading the first row, when the skill being
 * practised is noticing that OneDriveSync pointing at a world-writable
 * directory does not belong beside OneDrive pointing at Program Files.
 */
function persistenceRows(
  request: LiveResponseRequest,
  events: readonly SimulationEvent[],
): readonly LiveResponseRow[] {
  const rows: LiveResponseRow[] = [];

  for (const entry of request.autoruns ??
    []) {
    rows.push({
      primary: entry.name,

      /*
        The target on the row, not the location.

        Location is identical on almost every entry -- one Run key holds the
        lot -- so showing it filled the only scannable column with the one
        field that never varies, while the target, which is the whole
        difference between OneDrive and OneDriveSync, sat behind an expand.
        Making an analyst open seven rows one at a time is busywork, not
        rigour.
      */
      secondary: entry.target,
      detail: entry.location,
      state: undefined,
      basis: undefined,
      eventId: undefined,
      origin: "baseline",
      timestamp: undefined,
    });
  }

  for (const event of events) {
    if (
      event.type !== "PROCESS_STARTED" ||
      event.payload.deviceId !==
        request.deviceId
    ) {
      continue;
    }

    const parsed = parseInstall(
      event.payload.commandLine ?? "",
    );

    if (!parsed) {
      continue;
    }

    rows.push({
      primary: parsed.name,
      secondary: parsed.target,
      detail: parsed.location,
      state: undefined,
      basis: `Established ${describeAge(
        minutesBetween(
          event.timestamp,
          request.now,
        ),
      )}, while the sensor was watching. The rest of this list was configured before the window opened.`,
      eventId: event.id,
      origin: "observed",
      timestamp: event.timestamp,
    });
  }

  return rows.sort((left, right) => {
    const byLocation = (
      left.detail ?? ""
    ).localeCompare(right.detail ?? "");

    return byLocation !== 0
      ? byLocation
      : left.primary.localeCompare(
          right.primary,
        );
  });
}

function logonRows(
  request: LiveResponseRequest,
  events: readonly SimulationEvent[],
): readonly LiveResponseRow[] {
  const open = new Map<
    EntityId,
    LiveResponseRow
  >();

  for (const event of events) {
    if (
      event.type === "SESSION_STARTED" &&
      event.payload.deviceId ===
        request.deviceId
    ) {
      open.set(event.payload.sessionId, {
        primary: event.payload.accountId,
        secondary: `session ${event.payload.sessionId}`,
        detail: `Opened ${describeAge(
          minutesBetween(
            event.timestamp,
            request.now,
          ),
        )}`,
        state: undefined,
        basis: undefined,
        eventId: event.id,
        origin: "observed",
        timestamp: event.timestamp,
      });

      continue;
    }

    if (event.type === "SESSION_REVOKED") {
      open.delete(event.payload.sessionId);
    }
  }

  return [...open.values()].sort(
    newestFirst,
  );
}

function fileRows(
  request: LiveResponseRequest,
  events: readonly SimulationEvent[],
): readonly LiveResponseRow[] {
  const rows: LiveResponseRow[] = [];

  for (const event of events) {
    if (
      event.type !== "FILE_ACCESSED" ||
      event.payload.deviceId !==
        request.deviceId ||
      event.payload.operation === "read"
    ) {
      continue;
    }

    rows.push({
      primary: event.payload.fileId,
      secondary: event.payload.operation,
      detail: event.payload.accountId
        ? `by ${event.payload.accountId}`
        : undefined,
      state: undefined,
      basis: undefined,
      eventId: event.id,
      origin: "observed",
      timestamp: event.timestamp,
    });
  }

  return rows.sort(newestFirst);
}

const LIMITATIONS: Record<
  LiveResponseCommandId,
  string
> = {
  processes: `Process exit is not recorded by this sensor. A process is called running only where something was attributed to it in the last ${ACTIVE_WINDOW_MINUTES} minutes, exited only where the program is one that does its work and returns, and unknown otherwise. The listing covers the last ${PROCESS_LOOKBACK_HOURS} hours.`,

  connections:
    "Grouped by destination and process. Repetition to one address is what automation looks like, and legitimate software polling mail or chat looks the same -- the process is the field that separates them.",

  persistence:
    "What the host is configured to start, plus anything seen being installed during this window. Most of an estate's autorun entries are legitimate and predate any incident, so the question is never whether a host has persistence -- it is which entry does not belong beside the others.",

  logons:
    "Sessions opened on this host and not since revoked. A session the corpus never saw end is still listed as open.",

  files:
    "Writes, creations and deletions on this host. Reads are excluded: at corpus volume they bury everything else, and the endpoint console lists them in full.",
};

export function runLiveResponse(
  request: LiveResponseRequest,
): LiveResponseResult {
  const events = visibleEvents(request);

  const host = resolveHost(
    request.deviceId,
    events,
  );

  /*
    A silent host returns nothing, and says why.

    Returning historical rows for a machine that is not answering would be the
    worst thing this console could do. It would look like live state and be
    nothing of the kind, and the responder would act on a picture of a machine
    that may have been rebuilt hours ago.
  */
  if (
    host.reachability === "not-reporting"
  ) {
    return {
      command: request.command,
      host,
      rows: [],
      limitation:
        LIMITATIONS[request.command],
    };
  }

  const rows =
    request.command === "processes"
      ? processRows(request, events)
      : request.command === "connections"
        ? connectionRows(request, events)
        : request.command === "persistence"
          ? persistenceRows(request, events)
          : request.command === "logons"
            ? logonRows(request, events)
            : fileRows(request, events);

  return {
    command: request.command,
    host,
    rows,
    limitation:
      LIMITATIONS[request.command],
  };
}
