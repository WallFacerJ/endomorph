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

  /**
   * Connections to a single held-open service per workstation per day.
   *
   * Benign periodic traffic to a fixed address. Without it, repetition is a
   * free discriminator and beacon detection scores far better here than it
   * would anywhere real.
   */
  readonly pollsPerWorkstation: number;

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
    pollsPerWorkstation: 6,
    connectionsPerWorkstation: 11,
    fileAccessRate: 0.35,
  };

/**
 * A benign process and what launched it.
 *
 * Parent lineage is the field detection engineers reach for first, because
 * the child alone is almost never conclusive: powershell.exe is run all day
 * by administrators and by scheduled work. Modelling it here is what lets a
 * rule be *wrong* in an interesting way -- see the scheduled PowerShell
 * below, which is parented by the Task Scheduler exactly as a great deal of
 * malicious PowerShell is.
 */
interface BenignProcess {
  readonly image: string;
  readonly commandLine: string;
  readonly parentImage: string;
}

const WINDOWS_PROCESSES: readonly BenignProcess[] =
  [
  {
    image:
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    commandLine: "OUTLOOK.EXE",
    parentImage:
      "C:\\Windows\\explorer.exe",
  },
  {
    image:
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    commandLine: "EXCEL.EXE /dde",
    parentImage:
      "C:\\Windows\\explorer.exe",
  },
  {
    image:
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    commandLine:
      "chrome.exe --restore-last-session",
    parentImage:
      "C:\\Windows\\explorer.exe",
  },
  {
    image:
      "C:\\Program Files\\Microsoft Teams\\current\\Teams.exe",
    commandLine: "Teams.exe --minimized",
    parentImage:
      "C:\\Windows\\explorer.exe",
  },
  {
    image:
      "C:\\Windows\\System32\\svchost.exe",
    commandLine:
      "svchost.exe -k netsvcs -p",
    parentImage:
      "C:\\Windows\\System32\\services.exe",
  },
  {
    image:
      "C:\\Windows\\System32\\taskhostw.exe",
    commandLine: "taskhostw.exe {SYSTEM}",
    parentImage:
      "C:\\Windows\\System32\\svchost.exe",
  },
  {
    image:
      "C:\\Windows\\System32\\MsMpEng.exe",
    commandLine: "MsMpEng.exe",
    parentImage:
      "C:\\Windows\\System32\\services.exe",
  },
  {
    image:
      "C:\\Program Files\\Notepad++\\notepad++.exe",
    commandLine: "notepad++.exe",
    parentImage:
      "C:\\Windows\\explorer.exe",
  },
  {
    image:
      "C:\\Windows\\explorer.exe",
    commandLine: "explorer.exe",
    parentImage:
      "C:\\Windows\\System32\\userinit.exe",
  },
  {
    image:
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    commandLine:
      "powershell.exe -NoProfile -Command Get-MailboxStatistics",
    parentImage:
      "C:\\Windows\\System32\\svchost.exe",
  },
];

const MACOS_PROCESSES: readonly BenignProcess[] =
  [
  {
    image:
      "/Applications/Safari.app/Contents/MacOS/Safari",
    commandLine: "Safari",
    parentImage:
      "/sbin/launchd",
  },
  {
    image:
      "/Applications/Slack.app/Contents/MacOS/Slack",
    commandLine: "Slack",
    parentImage:
      "/sbin/launchd",
  },
  {
    image: "/usr/bin/ssh",
    commandLine: "ssh app-01",
    parentImage:
      "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
  },
  {
    image: "/bin/zsh",
    commandLine: "-zsh",
    parentImage:
      "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
  },
  {
    image:
      "/usr/libexec/mdworker_shared",
    commandLine:
      "mdworker_shared -s mdworker",
    parentImage:
      "/sbin/launchd",
  },
  {
    image:
      "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight",
    commandLine: "Spotlight",
    parentImage:
      "/sbin/launchd",
  },
];

const LINUX_PROCESSES: readonly BenignProcess[] =
  [
  {
    image: "/usr/bin/bash",
    commandLine: "-bash",
    parentImage:
      "/usr/bin/sshd",
  },
  {
    image: "/usr/bin/sshd",
    commandLine: "sshd: accepted",
    parentImage:
      "/usr/lib/systemd/systemd",
  },
  {
    image: "/usr/bin/systemd",
    commandLine:
      "/lib/systemd/systemd --user",
    parentImage:
      "/usr/lib/systemd/systemd",
  },
  {
    image: "/usr/bin/docker",
    commandLine: "docker ps",
    parentImage:
      "/usr/bin/bash",
  },
  {
    image: "/usr/bin/curl",
    commandLine:
      "curl -s https://packages.internal/health",
    parentImage:
      "/usr/lib/systemd/systemd",
  },
  {
    image: "/usr/bin/python3",
    commandLine:
      "python3 /opt/jobs/reconcile.py",
    parentImage:
      "/usr/lib/systemd/systemd",
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
): readonly BenignProcess[] {
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

/**
 * The programs on a workstation that talk to the network.
 *
 * Connections have to be attributed to something. Attributing them to a
 * process drawn from the general pool would put outbound 443 traffic under
 * taskhostw.exe and MsMpEng.exe, which is worse than leaving the field
 * empty: it teaches an analyst a lineage that does not occur.
 *
 * The first entry is the one that polls all day -- mail or chat -- because
 * that is the process the keepalive traffic belongs to.
 */
interface NetworkClient {
  readonly image: string;
}

const WINDOWS_NETWORK_CLIENTS: readonly NetworkClient[] =
  [
  {
    image:
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
  },
  {
    image:
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  },
  {
    image:
      "C:\\Program Files\\Microsoft Teams\\current\\Teams.exe",
  },
  {
    image:
      "C:\\Windows\\System32\\svchost.exe",
  },
];

const MACOS_NETWORK_CLIENTS: readonly NetworkClient[] =
  [
  {
    image:
      "/Applications/Slack.app/Contents/MacOS/Slack",
  },
  {
    image:
      "/Applications/Safari.app/Contents/MacOS/Safari",
  },
  { image: "/usr/bin/ssh" },
];

/*
  sshd is deliberately absent. It is the server side of the protocol and
  accepts connections rather than making them, so attributing outbound
  traffic to it would put a backwards lineage in front of an analyst -- the
  sort of detail that costs a product its credibility with the people who
  know the platform.
*/
const LINUX_NETWORK_CLIENTS: readonly NetworkClient[] =
  [
  { image: "/usr/bin/curl" },
  { image: "/usr/bin/ssh" },
  { image: "/usr/bin/docker" },
];


/**
 * Software that legitimately installs itself to start with the machine.
 *
 * Without these the corpus contained exactly one run-key write in the whole
 * estate -- the intrusion's -- and the rule that looks for them scored
 * perfect precision. That number was measuring the corpus, not the rule.
 * Installers, updaters and asset agents write autorun entries from a command
 * line constantly, and a rule that cannot tell one from malware should be
 * shown to be unable to tell one from malware.
 *
 * It is also what makes asking a host "what starts with you?" a real
 * question. If the only host in the estate with an autorun entry were the
 * compromised one, the answer would give the incident away.
 */
interface AutorunInstall {
  readonly image: string;
  readonly commandLine: string;
  readonly parentImage: string;
}

const WINDOWS_AUTORUNS: readonly AutorunInstall[] =
  [
  {
    image: "C:\\Windows\\System32\\reg.exe",
    commandLine:
      'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v OneDrive /t REG_SZ /d "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background" /f',
    parentImage: "C:\\Windows\\System32\\cmd.exe",
  },
  {
    image: "C:\\Windows\\System32\\reg.exe",
    commandLine:
      'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Teams /t REG_SZ /d "C:\\Program Files\\Microsoft Teams\\current\\Teams.exe --minimized" /f',
    parentImage: "C:\\Windows\\System32\\cmd.exe",
  },
  {
    image: "C:\\Windows\\System32\\reg.exe",
    commandLine:
      'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v ZoomUpdater /t REG_SZ /d "C:\\Program Files\\Zoom\\bin\\Zoom.exe --autostart" /f',
    parentImage: "C:\\Windows\\System32\\cmd.exe",
  },
  {
    image: "C:\\Windows\\System32\\reg.exe",
    commandLine:
      'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AcmeAssetAgent /t REG_SZ /d "C:\\Program Files\\Acme\\AssetAgent\\agent.exe --service" /f',
    parentImage: "C:\\Windows\\System32\\cmd.exe",
  },
];

const MACOS_AUTORUNS: readonly AutorunInstall[] =
  [
  {
    image: "/bin/launchctl",
    commandLine:
      "launchctl load -w /Library/LaunchAgents/com.acme.assetagent.plist",
    parentImage: "/bin/zsh",
  },
  {
    image: "/bin/launchctl",
    commandLine:
      "launchctl load -w /Library/LaunchAgents/com.microsoft.update.agent.plist",
    parentImage: "/bin/zsh",
  },
];

const LINUX_AUTORUNS: readonly AutorunInstall[] =
  [
  {
    image: "/usr/bin/systemctl",
    commandLine:
      "systemctl --user enable --now acme-asset-agent.service",
    parentImage: "/usr/bin/bash",
  },
  {
    image: "/usr/bin/systemctl",
    commandLine:
      "systemctl enable --now node-exporter.service",
    parentImage: "/usr/bin/bash",
  },
];

function autorunsFor(
  operatingSystem: string,
): readonly AutorunInstall[] {
  if (
    operatingSystem.startsWith("Windows")
  ) {
    return WINDOWS_AUTORUNS;
  }

  if (operatingSystem.startsWith("macOS")) {
    return MACOS_AUTORUNS;
  }

  return LINUX_AUTORUNS;
}

function networkClientsFor(
  operatingSystem: string,
): readonly NetworkClient[] {
  if (
    operatingSystem.startsWith("Windows")
  ) {
    return WINDOWS_NETWORK_CLIENTS;
  }

  if (operatingSystem.startsWith("macOS")) {
    return MACOS_NETWORK_CLIENTS;
  }

  return LINUX_NETWORK_CLIENTS;
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

    // One pid per parent image per host, not one per child. explorer.exe is
    // a single long-lived process; drawing a fresh pid for each of its
    // children would put nine different explorer.exe pids on one host and
    // make the lineage unpivotable -- the exact analysis the field exists to
    // support. Drawn lazily from a dedicated fork so the assignment does not
    // depend on how many children happen to be generated.
    const parentPidCursor =
      cursor.fork("parent-pids");

    /*
      Which program each connection belongs to.

      Both cursors below are dedicated forks. Attribution has to leave the
      existing draws untouched -- pulling from the network cursor would shift
      every port and destination after it and silently regenerate the whole
      corpus, which is the one thing this generator must not do by accident.

      Pids are stable per image per host for the same reason parent pids are:
      a browser is one long-lived process, and a fresh pid per connection
      would make the traffic unpivotable.
    */
    const networkClients =
      networkClientsFor(
        device.operatingSystem,
      );

    const clientPidCursor = cursor.fork(
      "net-client-pids",
    );

    const clientPids = new Map<
      string,
      string
    >();

    const clientPidFor = (
      image: string,
    ): string => {
      const existing =
        clientPids.get(image);

      if (existing !== undefined) {
        return existing;
      }

      const pid = String(
        clientPidCursor.nextInt(
          1000,
          65000,
        ),
      );

      clientPids.set(image, pid);

      return pid;
    };

    const attributionCursor = cursor.fork(
      "net-attribution",
    );

    const parentPids = new Map<
      string,
      string
    >();

    const parentPidFor = (
      image: string,
    ): string => {
      const existing =
        parentPids.get(image);

      if (existing !== undefined) {
        return existing;
      }

      const pid = String(
        parentPidCursor.nextInt(500, 999),
      );

      parentPids.set(image, pid);

      return pid;
    };

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
            parentImage:
              chosenProcess.parentImage,
            parentProcessId: parentPidFor(
              chosenProcess.parentImage,
            ),
            accountId: account.id,
          },
        },
      );
    }

    /*
      Occasional software installs, not a daily event.

      The rate is deliberately low. What this rule can match is a run key
      written from a *command line*, and most software writes the registry
      through the API instead -- it is deployment scripts and IT automation
      that shell out to reg.exe. A dozen across a week in a 120-person
      estate is the right order of magnitude; hundreds would be a different
      lie from the one this fixes.
    */
    const autorunCursor = cursor.fork(
      "autorun-installs",
    );

    if (autorunCursor.nextBoolean(0.02)) {
      const install = autorunCursor.pick(
        autorunsFor(
          device.operatingSystem,
        ),
      );

      push(
        arrival +
          dayOffset +
          autorunCursor.nextInt(
            1,
            Math.max(
              2,
              durationMinutes - arrival,
            ),
          ),
        `d${dayIndex}-${device.id}-autorun`,
        {
          type: "PROCESS_STARTED",
          source: "edr",
          subjectId: device.id,
          payload: {
            deviceId: device.id,
            processId: String(
              autorunCursor.nextInt(
                1000,
                65000,
              ),
            ),
            image: install.image,
            commandLine:
              install.commandLine,
            parentImage:
              install.parentImage,
            parentProcessId: parentPidFor(
              install.parentImage,
            ),
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

      const client =
        attributionCursor.pick(
          networkClients,
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
            processId: clientPidFor(
              client.image,
            ),
            image: client.image,
          },
        },
      );
    }

    // -- persistent service polling ----------------------------------------
    //
    // Ordinary traffic above picks a fresh destination for every connection,
    // which meant no benign host ever contacted the same external address
    // twice in a short window. Any rule keyed on repetition therefore scored
    // perfect precision against this corpus and would not have survived
    // contact with a real network -- the corpus was flattering the rule
    // rather than testing it.
    //
    // Corporate laptops hold polling connections open to mail and chat all
    // day, at an interval, to a fixed address. That is the same shape as a
    // beacon, and it is the reason beacon detection is hard. Modelling it is
    // what makes the measured precision of such a rule mean anything.
    const keepaliveCursor = cursor.fork(
      "keepalive",
    );

    const polled = keepaliveCursor.pick(
      EXTERNAL_DESTINATIONS,
    );

    // First entry by convention: the program that polls all day.
    const pollingClient =
      networkClients[0] as NetworkClient;

    const pollStart =
      arrival +
      keepaliveCursor.nextInt(1, 30);

    const pollInterval =
      keepaliveCursor.nextInt(4, 11);

    for (
      let index = 0;
      index < options.pollsPerWorkstation;
      index += 1
    ) {
      const offset =
        pollStart + index * pollInterval;

      if (
        offset >
        arrival + durationMinutes
      ) {
        break;
      }

      push(
        offset + dayOffset,
        `d${dayIndex}-${device.id}-poll-${index}`,
        {
          type: "NETWORK_CONNECTION",
          source: "network",
          subjectId: device.id,
          payload: {
            deviceId: device.id,
            protocol: "tcp",
            sourceIp,
            destinationIp: polled,
            sourcePort:
              keepaliveCursor.nextInt(
                49152,
                65535,
              ),
            destinationPort: 443,

            /*
              The polling client, not a random one. This traffic is a mail or
              chat client holding a connection open, and it is the same shape
              as a beacon -- one long-lived process, one fixed address, 443,
              at a steady interval. Now that the process travels with the
              connection, that is the field that tells the two apart, which
              is exactly the discrimination the real job requires.
            */
            processId: clientPidFor(
              pollingClient.image,
            ),
            image: pollingClient.image,
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
  // Identity administration (benign)
  // -----------------------------------------------------------------------
  // Real directories are not static: accounts are re-enabled for returning
  // staff, and non-privileged roles are granted through ordinary access
  // requests. With none of this, the corpus is trivially clean for the
  // identity-lifecycle techniques -- a rule keyed on "an account was enabled"
  // scores a perfect precision it would never see in production, and the noise
  // floor reports the technique as exposed. A handful of benign events per
  // window gives those techniques a realistic false-positive floor.
  //
  // The grants are deliberately of non-privileged roles. The rule that watches
  // for privilege escalation keys on administrative roles, so it stays clean
  // against these, while a naive rule keyed on "any role granted" does not --
  // which is the honest lesson: specificity is what separates a usable rule
  // from a noisy one, and the corpus has to contain the noise for that to mean
  // anything. Forked off the root so it disturbs no other stream.

  const identityCursor = root.fork(
    "identity-admin",
  );

  const adminActorId =
    enterprise.privilegedAccountIds[0] ??
    enterprise.accounts[0]?.id;

  const ordinaryAccounts =
    enterprise.accounts.filter(
      (account) =>
        !account.id.endsWith("-adm"),
    );

  if (
    adminActorId &&
    ordinaryAccounts.length > 0
  ) {
    const NON_PRIVILEGED_ROLES = [
      "reports-viewer",
      "expense-approver",
      "wiki-editor",
      "billing-reader",
      "helpdesk-agent",
    ];

    const businessMinute = (
      cursor: typeof identityCursor,
    ): number =>
      // Working hours of the first day, before the incident begins. The
      // detection-evaluation corpus is the pre-detection slice of the
      // history, and an intrusion is planted a few hours into the first day,
      // so an administrative action buried in that morning is both realistic
      // and actually present in the corpus a rule is scored against -- an
      // event placed later would be generated and then filtered straight back
      // out, which is how the first draft of this quietly changed nothing.
      30 + cursor.nextInt(0, 410);

    const grantCursor =
      identityCursor.fork("role-grants");

    const grants = Math.min(
      4,
      ordinaryAccounts.length,
    );

    for (
      let index = 0;
      index < grants;
      index += 1
    ) {
      const cursor = grantCursor.fork(
        `grant-${index}`,
      );

      const target = cursor.pick(
        ordinaryAccounts,
      );

      push(
        businessMinute(cursor),
        `identity-grant-${index}`,
        {
          type: "ROLE_GRANTED",
          source: "identity",
          actorId: adminActorId,
          subjectId: target.id,
          payload: {
            accountId: target.id,
            role: cursor.pick(
              NON_PRIVILEGED_ROLES,
            ),
            ...(identityApplication
              ? {
                  applicationId:
                    identityApplication.id,
                }
              : {}),
            reason:
              "Access request approved",
          },
        },
      );
    }

    const enableCursor =
      identityCursor.fork(
        "account-enables",
      );

    const enables = Math.min(
      2,
      ordinaryAccounts.length,
    );

    for (
      let index = 0;
      index < enables;
      index += 1
    ) {
      const cursor = enableCursor.fork(
        `enable-${index}`,
      );

      const target = cursor.pick(
        ordinaryAccounts,
      );

      push(
        businessMinute(cursor),
        `identity-enable-${index}`,
        {
          type: "ACCOUNT_ENABLED",
          source: "identity",
          actorId: adminActorId,
          subjectId: target.id,
          payload: {
            accountId: target.id,
            reason:
              "Returning employee reactivation",
          },
        },
      );
    }

    // Benign mail, so the phishing plan's spearphishing-link technique has the
    // look-alikes a real inbox carries: external senders, some with links and
    // attachments. A rule that fires on "external mail with a link" has to eat
    // all of this; only one that reads the link's destination clears it.
    const BENIGN_MAIL: readonly {
      readonly sender: string;
      readonly display: string;
      readonly subject: string;
      readonly external: boolean;
      readonly url?: string;
      readonly attachment?: string;
    }[] = [
      {
        sender: "newsletter@industry-weekly.example",
        display: "Industry Weekly",
        subject: "This week in security operations",
        external: true,
        url: "https://industry-weekly.example/read/latest",
      },
      {
        sender: "billing@cloud-vendor.example",
        display: "Cloud Vendor Billing",
        subject: "Your July invoice is ready",
        external: true,
        url: "https://portal.cloud-vendor.example/invoices",
      },
      {
        sender: "no-reply@calendar.example",
        display: "Calendar",
        subject: "Reminder: quarterly planning at 14:00",
        external: true,
      },
      {
        sender: "hr-announcements@internal.example",
        display: "People Team",
        subject: "Updated travel policy (effective Monday)",
        external: false,
        attachment: "Travel_Policy_v4.pdf",
      },
      {
        sender: "it-helpdesk@internal.example",
        display: "IT Helpdesk",
        subject: "Scheduled maintenance this weekend",
        external: false,
      },
      {
        sender: "orders@office-supplies.example",
        display: "Office Supplies",
        subject: "Your order has shipped",
        external: true,
        url: "https://office-supplies.example/track/8842",
      },
      {
        sender: "team-lead@internal.example",
        display: "Team Lead",
        subject: "Notes from today's stand-up",
        external: false,
        attachment: "Standup_Notes.docx",
      },
      {
        sender: "security-digest@vendor.example",
        display: "Vendor Security",
        subject: "Monthly patch summary",
        external: true,
        url: "https://vendor.example/patch-notes/august",
      },
    ];

    const mailCursor = root.fork("mail");

    const mailCount = Math.min(
      16,
      ordinaryAccounts.length,
    );

    for (
      let index = 0;
      index < mailCount;
      index += 1
    ) {
      const cursor = mailCursor.fork(
        `mail-${index}`,
      );

      const recipient = cursor.pick(
        ordinaryAccounts,
      );

      const template = cursor.pick(
        BENIGN_MAIL,
      );

      push(
        businessMinute(cursor),
        `mail-${index}`,
        {
          type: "EMAIL_RECEIVED",
          source: "mail",
          subjectId: recipient.id,
          payload: {
            accountId: recipient.id,
            ...(recipient.userId
              ? { userId: recipient.userId }
              : {}),
            senderAddress:
              template.sender,
            senderDisplayName:
              template.display,
            subject: template.subject,
            external: template.external,
            ...(template.url
              ? { url: template.url }
              : {}),
            ...(template.attachment
              ? {
                  attachmentName:
                    template.attachment,
                }
              : {}),
          },
        },
      );
    }

    // Benign cloud control-plane activity, so the consent-grant intrusion's
    // steps have look-alikes: legitimate app consents, routine credential
    // rotations, and storage enumeration by administrators and CI. None of it
    // copies data to an external account, which is the one thing the malicious
    // exfil does and benign operations never do.
    const BENIGN_CLOUD: readonly {
      readonly action: string;
      readonly service: string;
      readonly app?: string;
      readonly resource?: string;
    }[] = [
      {
        action: "ConsentToApplication",
        service: "EntraID",
        app: "Slack",
        resource: "User.Read",
      },
      {
        action: "ConsentToApplication",
        service: "EntraID",
        app: "Zoom",
        resource: "User.Read, Calendars.Read",
      },
      {
        action: "CreateAccessKey",
        service: "IAM",
        resource: "ci-deploy",
      },
      {
        action: "ListStorageContainers",
        service: "Storage",
        resource: "tenant-storage-audit",
      },
      {
        action: "ListStorageContainers",
        service: "Storage",
        resource: "backups",
      },
      {
        action: "RotateAccessKey",
        service: "IAM",
        resource: "backup-service",
      },
      {
        action: "ConsentToApplication",
        service: "EntraID",
        app: "Salesforce",
        resource: "User.Read",
      },
    ];

    const cloudCursor =
      root.fork("cloud-audit");

    const cloudCount = Math.min(
      14,
      ordinaryAccounts.length,
    );

    for (
      let index = 0;
      index < cloudCount;
      index += 1
    ) {
      const cursor = cloudCursor.fork(
        `cloud-${index}`,
      );

      const account = cursor.pick(
        ordinaryAccounts,
      );

      const template = cursor.pick(
        BENIGN_CLOUD,
      );

      push(
        businessMinute(cursor),
        `cloud-${index}`,
        {
          type: "CLOUD_AUDIT",
          source: "cloud",
          subjectId: account.id,
          payload: {
            accountId: account.id,
            ...(account.userId
              ? { userId: account.userId }
              : {}),
            action: template.action,
            service: template.service,
            ...(template.app
              ? {
                  appDisplayName:
                    template.app,
                }
              : {}),
            ...(template.resource
              ? {
                  resource:
                    template.resource,
                }
              : {}),
            outcome: "success",
          },
        },
      );
    }

    // Benign DNS, so the beacon's high-entropy lookups and the tunnel's long
    // TXT names have the ordinary resolver traffic to hide among: pronounceable
    // registered domains, A records, a couple of short SPF-style TXT lookups.
    const BENIGN_DNS: readonly {
      readonly name: string;
      readonly type: string;
    }[] = [
      { name: "login.microsoftonline.com", type: "A" },
      { name: "outlook.office365.com", type: "A" },
      { name: "teams.microsoft.com", type: "A" },
      { name: "www.google.com", type: "A" },
      { name: "cdn.jsdelivr.net", type: "A" },
      { name: "github.com", type: "A" },
      { name: "slack.com", type: "A" },
      { name: "update.googleapis.com", type: "A" },
      { name: "_dmarc.acme.test", type: "TXT" },
      { name: "acme.test", type: "TXT" },
    ];

    const dnsCursor = root.fork("dns");

    const dnsCount = Math.min(
      24,
      ordinaryAccounts.length,
    );

    for (
      let index = 0;
      index < dnsCount;
      index += 1
    ) {
      const cursor = dnsCursor.fork(
        `dns-${index}`,
      );

      const template = cursor.pick(
        BENIGN_DNS,
      );

      push(
        businessMinute(cursor),
        `dns-${index}`,
        {
          type: "DNS_QUERY",
          source: "network",
          payload: {
            queryName: template.name,
            queryType: template.type,
          },
        },
      );
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
