import type {
  SimulationEvent,
} from "@endomorph/simulation";

import {
  RandomCursor,
} from "./randomCursor.js";

import {
  APPLICATION_PROFILES,
} from "./nameLibrary.js";

import type {
  GeneratedEnterprise,
} from "./generateEnterprise.js";

/**
 * Benign enterprise activity.
 *
 * This is the noise floor. Without it the Ops tools show a short curated
 * list where every row is suspicious, which is exactly the "read the alert,
 * pick the answer" experience the product is trying to leave behind. An
 * analyst should have to search, filter, and correlate to find the handful
 * of events that matter.
 *
 * Everything here is derived from the enterprise, a seed, and virtual time.
 * No wall-clock reads, no unseeded randomness.
 */

export interface ActivityOptions {
  /**
   * Consecutive days of history to generate, ending on the day the incident
   * lands.
   *
   * History is what makes an observation anomalous. "This account signed in
   * from an address it has never used" is unanswerable against a single
   * day; against a week of habitual behaviour it is the whole case. Staff
   * keep stable habits across days -- same workstation, same address, same
   * handful of applications, similar arrival time -- and vary only within
   * them.
   */
  readonly days: number;

  /** Length of the generated working day, in hours. */
  readonly durationHours: number;

  /** Minutes between endpoint heartbeats per active device. */
  readonly heartbeatIntervalMinutes: number;

  /** Applications an average staff member signs into during the day. */
  readonly averageApplicationLogins: number;

  /** Chance a staff member mistypes a password at least once. */
  readonly typoRate: number;

  /** Business processes launched per active workstation. */
  readonly processesPerWorkstation: number;

  /** Outbound/internal connections per active workstation. */
  readonly connectionsPerWorkstation: number;

  /** Chance an active staff member touches a shared document. */
  readonly fileAccessRate: number;
}

export const DEFAULT_ACTIVITY_OPTIONS: ActivityOptions =
  {
    days: 5,
    durationHours: 10,
    heartbeatIntervalMinutes: 45,
    averageApplicationLogins: 3,
    typoRate: 0.22,
    processesPerWorkstation: 9,
    connectionsPerWorkstation: 11,
    fileAccessRate: 0.35,
  };

const WINDOWS_PROCESSES: readonly {
  image: string;
  commandLine: string;
}[] = [
  {
    image:
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    commandLine: "OUTLOOK.EXE",
  },
  {
    image:
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    commandLine: "EXCEL.EXE /dde",
  },
  {
    image:
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    commandLine:
      "chrome.exe --restore-last-session",
  },
  {
    image:
      "C:\\Program Files\\Microsoft Teams\\current\\Teams.exe",
    commandLine: "Teams.exe --minimized",
  },
  {
    image:
      "C:\\Windows\\System32\\svchost.exe",
    commandLine:
      "svchost.exe -k netsvcs -p",
  },
  {
    image:
      "C:\\Windows\\System32\\taskhostw.exe",
    commandLine: "taskhostw.exe {SYSTEM}",
  },
  {
    image:
      "C:\\Windows\\System32\\MsMpEng.exe",
    commandLine: "MsMpEng.exe",
  },
  {
    image:
      "C:\\Program Files\\Notepad++\\notepad++.exe",
    commandLine: "notepad++.exe",
  },
  {
    image:
      "C:\\Windows\\explorer.exe",
    commandLine: "explorer.exe",
  },
  {
    image:
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    commandLine:
      "powershell.exe -NoProfile -Command Get-MailboxStatistics",
  },
];

const MACOS_PROCESSES: readonly {
  image: string;
  commandLine: string;
}[] = [
  {
    image:
      "/Applications/Safari.app/Contents/MacOS/Safari",
    commandLine: "Safari",
  },
  {
    image:
      "/Applications/Slack.app/Contents/MacOS/Slack",
    commandLine: "Slack",
  },
  {
    image: "/usr/bin/ssh",
    commandLine: "ssh app-01",
  },
  {
    image: "/bin/zsh",
    commandLine: "-zsh",
  },
  {
    image:
      "/usr/libexec/mdworker_shared",
    commandLine:
      "mdworker_shared -s mdworker",
  },
  {
    image:
      "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight",
    commandLine: "Spotlight",
  },
];

const LINUX_PROCESSES: readonly {
  image: string;
  commandLine: string;
}[] = [
  {
    image: "/usr/bin/bash",
    commandLine: "-bash",
  },
  {
    image: "/usr/bin/sshd",
    commandLine: "sshd: accepted",
  },
  {
    image: "/usr/bin/systemd",
    commandLine:
      "/lib/systemd/systemd --user",
  },
  {
    image: "/usr/bin/docker",
    commandLine: "docker ps",
  },
  {
    image: "/usr/bin/curl",
    commandLine:
      "curl -s https://packages.internal/health",
  },
  {
    image: "/usr/bin/python3",
    commandLine:
      "python3 /opt/jobs/reconcile.py",
  },
];

/** Routine external destinations, so outbound traffic is not all internal. */
const MINUTES_PER_DAY = 1440;

const EXTERNAL_DESTINATIONS: readonly string[] =
  [
    "52.96.104.11",
    "142.250.187.14",
    "13.107.42.14",
    "104.18.32.47",
    "151.101.65.69",
    "34.117.59.81",
    "20.42.65.92",
  ];

function processPoolFor(
  operatingSystem: string,
): readonly {
  image: string;
  commandLine: string;
}[] {
  if (
    operatingSystem.startsWith("Windows")
  ) {
    return WINDOWS_PROCESSES;
  }

  if (operatingSystem.startsWith("macOS")) {
    return MACOS_PROCESSES;
  }

  return LINUX_PROCESSES;
}

function isoAt(
  startMilliseconds: number,
  offsetMinutes: number,
): string {
  return new Date(
    startMilliseconds +
      Math.round(offsetMinutes * 60000),
  ).toISOString();
}

/**
 * Generates a working day of benign activity across the enterprise.
 *
 * Returns events sorted by timestamp with deterministic sequential ids.
 */
export function generateBackgroundActivity(
  enterprise: GeneratedEnterprise,
  overrides: Partial<ActivityOptions> = {},
): SimulationEvent[] {
  const options = {
    ...DEFAULT_ACTIVITY_OPTIONS,
    ...overrides,
  };

  if (
    !Number.isFinite(
      options.durationHours,
    ) ||
    options.durationHours <= 0
  ) {
    throw new Error(
      "Activity durationHours must be positive.",
    );
  }

  if (
    !Number.isFinite(
      options.heartbeatIntervalMinutes,
    ) ||
    options.heartbeatIntervalMinutes <= 0
  ) {
    throw new Error(
      "Activity heartbeatIntervalMinutes must be positive.",
    );
  }

  if (
    !Number.isInteger(options.days) ||
    options.days < 1
  ) {
    throw new Error(
      "Activity days must be a positive integer.",
    );
  }

  const startMilliseconds = Date.parse(
    enterprise.profile.startTime,
  );

  const durationMinutes =
    options.durationHours * 60;

  const root = RandomCursor.root(
    enterprise.profile.seed,
  ).fork("background-activity");

  const events: {
    event: SimulationEvent;
    minute: number;
    tiebreak: string;
  }[] = [];

  const push = (
    minute: number,
    tiebreak: string,
    event: Omit<
      SimulationEvent,
      "id" | "timestamp"
    >,
  ): void => {
    events.push({
      minute,
      tiebreak,
      event: {
        ...event,
        id: "",
        timestamp: isoAt(
          startMilliseconds,
          minute,
        ),
      } as SimulationEvent,
    });
  };

  // -----------------------------------------------------------------------
  // Lookups
  // -----------------------------------------------------------------------

  const usersById = new Map(
    enterprise.users.map((user) => [
      user.id,
      user,
    ]),
  );

  const devicesById = new Map(
    enterprise.devices.map((device) => [
      device.id,
      device,
    ]),
  );

  const staffFacingNames = new Set(
    APPLICATION_PROFILES.filter(
      (application) =>
        application.staffFacing,
    ).map(
      (application) => application.name,
    ),
  );

  const staffFacingApplications =
    enterprise.applications.filter(
      (application) =>
        [...staffFacingNames].some(
          (name) =>
            application.name.endsWith(
              name,
            ),
        ),
    );

  const identityApplication =
    enterprise.applications.find(
      (application) =>
        application.kind === "identity",
    );

  const primaryAccountByUser = new Map(
    enterprise.users.map((user) => [
      user.id,
      enterprise.accounts.find(
        (account) =>
          account.userId === user.id &&
          !account.id.endsWith("-adm"),
      ),
    ]),
  );

  const heartbeatCursor =
    root.fork("heartbeats");

  const staffCursor = root.fork("staff");

  for (
    let dayIndex = 0;
    dayIndex < options.days;
    dayIndex += 1
  ) {
    const dayOffset =
      dayIndex * MINUTES_PER_DAY;

    // Weekends are quiet. A flat five days would make the incident day look
    // ordinary and would teach an analyst nothing about normal rhythm.
    const weekday = new Date(
      startMilliseconds +
        dayOffset * 60000,
    ).getUTCDay();

    const isWeekend =
      weekday === 0 || weekday === 6;

  // -----------------------------------------------------------------------
  // Endpoint heartbeats
  // -----------------------------------------------------------------------

  for (const device of enterprise.devices) {
    if (device.status !== "active") {
      continue;
    }

    const cursor = heartbeatCursor
      .fork(device.id)
      .fork(`day-${dayIndex}`);

    // Stagger the first beat so the fleet does not report in lockstep.
    let minute = cursor.nextInt(
      0,
      options.heartbeatIntervalMinutes,
    );

    let beat = 0;

    while (minute < durationMinutes) {
      push(
        minute + dayOffset,
        `d${dayIndex}-${device.id}-hb-${beat}`,
        {
          type: "ENDPOINT_HEARTBEAT",
          source: "edr",
          subjectId: device.id,
          payload: {
            deviceId: device.id,
            status: "active",
            ipAddresses:
              device.ipAddresses,
          },
        },
      );

      minute +=
        options.heartbeatIntervalMinutes;

      beat += 1;
    }
  }

  // -----------------------------------------------------------------------
  // Per-staff working day
  // -----------------------------------------------------------------------

  for (const user of enterprise.users) {
    // Habits are forked from the person alone, so they are identical on
    // every day of the generated history. This is the baseline an analyst
    // reasons against.
    const habit = staffCursor.fork(
      user.id,
    );

    const habitualApplications = habit
      .shuffle(staffFacingApplications)
      .slice(
        0,
        habit.nextInt(2, 5),
      );

    const arrivalMean =
      25 + habit.nextInt(0, 55);

    // Day-to-day variation forks from the habit, so one day's activity
    // never shifts another's.
    const cursor = habit.fork(
      `day-${dayIndex}`,
    );

    const account =
      primaryAccountByUser.get(user.id);

    if (!account) {
      continue;
    }

    const device = user.deviceIds
      .map((deviceId) =>
        devicesById.get(deviceId),
      )
      .find(
        (candidate) =>
          candidate !== undefined,
      );

    const sourceIp =
      device?.ipAddresses[0] ??
      "10.90.0.10";

    // Dormant and disabled staff do not work a normal day. A disabled
    // account still generates the occasional failed sign-in, which is
    // realistic and gives an analyst benign-but-odd events to rule out.
    if (user.status !== "active") {
      if (cursor.nextBoolean(0.35)) {
        push(
          cursor.nextInt(
            0,
            durationMinutes,
          ) + dayOffset,
          `d${dayIndex}-${user.id}-stale-auth`,
          {
            type: "AUTH_LOGIN_FAILED",
            source: "identity",
            subjectId: user.id,
            payload: {
              username: account.username,
              reason:
                user.status ===
                "disabled"
                  ? "disabled_account"
                  : "invalid_credentials",
              applicationId:
                identityApplication?.id,
              sourceIp,
            },
          },
        );
      }

      continue;
    }

    // On a weekend only a small on-call minority works at all.
    if (
      isWeekend &&
      !cursor.nextBoolean(0.12)
    ) {
      continue;
    }

    // -- arrival ---------------------------------------------------------
    // Jitter around this person's habitual arrival time, so the morning
    // peak looks like a real office and each individual keeps a recognisable
    // routine across days.
    const arrival =
      arrivalMean +
      cursor.nextInt(0, 25) -
      12;

    if (
      cursor.nextBoolean(options.typoRate)
    ) {
      push(
        arrival - 1 + dayOffset,
        `d${dayIndex}-${user.id}-typo`,
        {
          type: "AUTH_LOGIN_FAILED",
          source: "identity",
          subjectId: user.id,
          payload: {
            username: account.username,
            reason: "invalid_credentials",
            applicationId:
              identityApplication?.id,
            deviceId: device?.id,
            sourceIp,
          },
        },
      );
    }

    push(
      arrival + dayOffset,
      `d${dayIndex}-${user.id}-auth`,
      {
        type: "AUTH_LOGIN_SUCCEEDED",
        source: "identity",
        actorId: account.id,
        subjectId: user.id,
        payload: {
          accountId: account.id,
          userId: user.id,
          deviceId: device?.id,
          applicationId:
            identityApplication?.id,
          sourceIp,
        },
      },
    );

    const sessionId = `session-${user.id}-day-${dayIndex}`;

    push(
      arrival + dayOffset,
      `d${dayIndex}-${user.id}-session`,
      {
        type: "SESSION_STARTED",
        source: "identity",
        actorId: account.id,
        subjectId: sessionId,
        payload: {
          sessionId,
          accountId: account.id,
          deviceId: device?.id,
          applicationId:
            identityApplication?.id,
        },
      },
    );

    // -- application sign-ins --------------------------------------------
    const applicationCount =
      cursor.nextInt(
        1,
        options.averageApplicationLogins *
          2,
      );

    const chosen = cursor
      .shuffle(habitualApplications)
      .slice(0, applicationCount);

    for (
      let index = 0;
      index < chosen.length;
      index += 1
    ) {
      const application = chosen[index];

      push(
        arrival +
          dayOffset +
          cursor.nextInt(
            2,
            Math.max(
              3,
              durationMinutes - arrival,
            ),
          ),
        `d${dayIndex}-${user.id}-app-${index}`,
        {
          type: "AUTH_LOGIN_SUCCEEDED",
          source: "identity",
          actorId: account.id,
          subjectId: user.id,
          payload: {
            accountId: account.id,
            userId: user.id,
            deviceId: device?.id,
            applicationId: application.id,
            sourceIp,
          },
        },
      );
    }

    if (!device) {
      continue;
    }

    // -- workstation processes -------------------------------------------
    const processCursor =
      cursor.fork("processes");

    const pool = processPoolFor(
      device.operatingSystem,
    );

    for (
      let index = 0;
      index <
      options.processesPerWorkstation;
      index += 1
    ) {
      const chosenProcess =
        processCursor.pick(pool);

      push(
        arrival +
          dayOffset +
          processCursor.nextInt(
            1,
            Math.max(
              2,
              durationMinutes - arrival,
            ),
          ),
        `d${dayIndex}-${device.id}-proc-${index}`,
        {
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: device.id,
          payload: {
            deviceId: device.id,
            processId: String(
              processCursor.nextInt(
                1000,
                65000,
              ),
            ),
            image: chosenProcess.image,
            commandLine:
              chosenProcess.commandLine,
            accountId: account.id,
          },
        },
      );
    }

    // -- workstation network traffic --------------------------------------
    const networkCursor =
      cursor.fork("network");

    for (
      let index = 0;
      index <
      options.connectionsPerWorkstation;
      index += 1
    ) {
      const internal =
        networkCursor.nextBoolean(0.55);

      const destination = internal
        ? `10.90.${networkCursor.nextInt(1, 20)}.${networkCursor.nextInt(2, 250)}`
        : networkCursor.pick(
            EXTERNAL_DESTINATIONS,
          );

      push(
        arrival +
          dayOffset +
          networkCursor.nextInt(
            1,
            Math.max(
              2,
              durationMinutes - arrival,
            ),
          ),
        `d${dayIndex}-${device.id}-net-${index}`,
        {
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: device.id,
          payload: {
            deviceId: device.id,
            protocol: "tcp",
            sourceIp,
            destinationIp: destination,
            sourcePort:
              networkCursor.nextInt(
                49152,
                65535,
              ),
            destinationPort: internal
              ? networkCursor.pick([
                  445, 389, 1433, 3389,
                  22,
                ])
              : networkCursor.pick([
                  443, 443, 443, 80,
                ]),
          },
        },
      );
    }

    // -- shared document access -------------------------------------------
    if (
      cursor.nextBoolean(
        options.fileAccessRate,
      )
    ) {
      const departmentFiles =
        enterprise.files.filter(
          (file) =>
            file.ownerUserId !==
              undefined &&
            usersById.get(
              file.ownerUserId,
            )?.department ===
              user.department,
        );

      if (departmentFiles.length > 0) {
        const file = cursor.pick(
          departmentFiles,
        );

        push(
          arrival +
            dayOffset +
            cursor.nextInt(
              5,
              Math.max(
                6,
                durationMinutes - arrival,
              ),
            ),
          `d${dayIndex}-${user.id}-file`,
          {
            type: "FILE_ACCESSED",
            source: "file_server",
            actorId: account.id,
            subjectId: file.id,
            payload: {
              fileId: file.id,
              operation:
                cursor.nextBoolean(0.7)
                  ? "read"
                  : "write",
              deviceId: device.id,
              accountId: account.id,
            },
          },
        );
      }
    }
  }
  }

  // -----------------------------------------------------------------------
  // Order and label
  // -----------------------------------------------------------------------

  events.sort(
    (left, right) =>
      left.minute - right.minute ||
      left.tiebreak.localeCompare(
        right.tiebreak,
      ),
  );

  return events.map(
    (entry, index) =>
      ({
        ...entry.event,
        id: `bg-${String(index + 1).padStart(6, "0")}`,
      }) as SimulationEvent,
  );
}
