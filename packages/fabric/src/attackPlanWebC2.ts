import type {
  AttackPlan,
} from "./attackPlan.js";

const DOWNLOAD_HOST = "cdn-updates.ru";
const C2_DOMAIN = "sync-telemetry.top";
const EXFIL_HOST = "paste.anon-share.top";
const MALWARE_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gh0st/2.1";

/**
 * Malicious download, web command-and-control, and HTTP exfiltration.
 *
 * The raw connection log shows a host talking to an address on port 443; the
 * proxy shows what the raw log cannot -- the URL of a payload downloaded over
 * HTTP, the hardcoded user agent a malware family beacons with, and the large
 * POST that carries data out to a paste site. Each is a line in the proxy log
 * and invisible to a connection-only view, and each is the kind of signal a web
 * analytic is written against.
 *
 * The lesson is that web detection reads the request, not the connection: the
 * download hides among thousands of benign GETs, but its host is a fresh
 * lookalike; the beacon hides among benign HTTPS, but its user agent is one no
 * real browser sends; the exfil hides among benign POSTs, but its destination
 * is an anonymous paste service.
 */
export const WEB_C2_PLAN: AttackPlan = {
  id: "web-c2",
  name: "Malicious download, web C2, and HTTP exfiltration",
  difficulty: "advanced",
  lesson:
    "This intrusion is written for the proxy log, not the connection log: a connection-only view sees a host talking to a few addresses on 443 and nothing more. The proxy sees the request -- a payload downloaded over HTTP from a fresh lookalike host, a beacon carrying a user agent no real browser sends, and a large POST to an anonymous paste service. Each hides among ordinary web traffic and is separated by what it asks for, so a rule that reads the URL and the user agent catches it while one that alerts on 'a web request' drowns.",
  requires: {},

  techniques: [
    {
      id: "T1105",
      name: "Ingress Tool Transfer",
      tactic: "command_and_control",
    },
    {
      id: "T1071.001",
      name: "Application Layer Protocol: Web Protocols",
      tactic: "command_and_control",
    },
    {
      id: "T1567.002",
      name: "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
      tactic: "exfiltration",
    },
  ],

  steps: [
    {
      id: "tool-download",
      title:
        "A payload is downloaded over HTTP from a fresh host",
      techniqueId: "T1105",
      advanceBy: 4,
      significance: (cast) =>
        `${cast.subjectDevice.hostname} downloaded an executable from ${DOWNLOAD_HOST} over plain HTTP — a host registered days ago and serving a single file.`,
      reasoning: () =>
        "A download on its own is the most ordinary web event there is; what marks this one is the host and the object. The domain is a fresh registration impersonating an update service, and the object is an executable served over plain HTTP rather than from a signed, known distribution point. Carry the host forward as an indicator and pivot on it across the proxy log — anyone else who fetched from it pulled the same payload, and the file's hash is what you will hunt for on disk.",
      build: (cast) => ({
        type: "WEB_REQUEST",
        source: "web",
        subjectId: cast.subjectDevice.id,
        payload: {
          deviceId: cast.subjectDevice.id,
          url: `http://${DOWNLOAD_HOST}/pkg/update.exe`,
          domain: DOWNLOAD_HOST,
          method: "GET",
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          statusCode: 200,
          bytesIn: 1_842_176,
          sourceIp: cast.subjectIp,
          destinationIp: cast.externalIp,
        },
      }),
    },
    {
      id: "web-c2",
      title:
        "The host beacons with a hardcoded user agent",
      techniqueId: "T1071.001",
      repeat: 3,
      advanceBy: 6,
      significance: (cast) =>
        `Regular requests from ${cast.subjectDevice.hostname} to ${C2_DOMAIN}, all carrying a user agent no browser on the estate sends.`,
      reasoning: () =>
        "Beaconing over HTTPS looks like any web traffic until you read the request header: the user agent is hardcoded into the malware and does not match any real browser or the versions deployed across the estate. That single field is the separator here — the destination rotates and the timing can be jittered, but the client identifies itself the same way every time. Pivot on the user agent across every host, because it finds the other infections the destination alone would miss.",
      build: (cast) => ({
        type: "WEB_REQUEST",
        source: "web",
        subjectId: cast.subjectDevice.id,
        payload: {
          deviceId: cast.subjectDevice.id,
          url: `https://${C2_DOMAIN}/gate.php`,
          domain: C2_DOMAIN,
          method: "GET",
          userAgent: MALWARE_UA,
          statusCode: 200,
          bytesIn: 512,
          sourceIp: cast.subjectIp,
          destinationIp: cast.c2Ip,
        },
      }),
    },
    {
      id: "web-exfil",
      title:
        "Data is POSTed to an anonymous paste service",
      techniqueId: "T1567.002",
      advanceBy: 3,
      significance: (cast) =>
        `A single large HTTP POST from ${cast.subjectDevice.hostname} to ${EXFIL_HOST}, uploading far more than any form submission would. This is the business impact.`,
      reasoning: () =>
        "This is the exfiltration, and it hides in plain sight among ordinary POSTs — a login, a form, an API call. What separates it is the pairing of destination and volume: an anonymous paste-and-share service, and an upload of megabytes where a form sends kilobytes. Measure what could have left by the byte count, and treat the destination as an indicator, but understand the data is already gone; the response now is about the credential and the host, not the upload.",
      build: (cast) => ({
        type: "WEB_REQUEST",
        source: "web",
        subjectId: cast.subjectDevice.id,
        payload: {
          deviceId: cast.subjectDevice.id,
          url: `https://${EXFIL_HOST}/upload`,
          domain: EXFIL_HOST,
          method: "POST",
          userAgent: MALWARE_UA,
          statusCode: 201,
          bytesOut: 9_437_184,
          sourceIp: cast.subjectIp,
          destinationIp: cast.externalIp,
        },
      }),
    },
  ],

  questions: [
    {
      id: "q-download",
      prompt: () =>
        "From which host was the payload downloaded?",
      accepted: () => [DOWNLOAD_HOST],
      hint: "Read the proxy log for an executable fetched over plain HTTP from a freshly-registered host.",
      surface: "siem",
      points: 25,
      evidenceStepId: "tool-download",
    },
    {
      id: "q-useragent",
      prompt: () =>
        "What User-Agent string did the beacon carry?",
      accepted: () => [
        MALWARE_UA,
        "Gh0st/2.1",
      ],
      hint: "It is the same on every beacon and matches no real browser on the estate.",
      surface: "siem",
      points: 25,
      evidenceStepId: "web-c2",
    },
    {
      id: "q-c2",
      prompt: () =>
        "Which domain did the host beacon to?",
      accepted: () => [C2_DOMAIN],
      hint: "Regular small GETs at a steady interval.",
      surface: "siem",
      points: 25,
      evidenceStepId: "web-c2",
    },
    {
      id: "q-exfil",
      prompt: () =>
        "To which host was data exfiltrated over an HTTP POST?",
      accepted: () => [EXFIL_HOST],
      hint: "A single POST far larger than any form submission.",
      surface: "siem",
      points: 25,
      evidenceStepId: "web-exfil",
    },
  ],

  alertTitle: () =>
    `Malware download and web command-and-control detected`,
  alertSeverity: "high",
  alertStepIds: ["web-c2"],

  summary: (cast) =>
    `${cast.subjectDevice.hostname} downloaded a payload over plain HTTP from the freshly-registered host ${DOWNLOAD_HOST}, then beaconed to ${C2_DOMAIN} carrying a hardcoded user agent no real browser sends, and finally POSTed roughly nine megabytes to the anonymous paste service ${EXFIL_HOST}. A connection log would show only traffic to a few addresses on 443; the whole intrusion is legible only in the proxy's view of the requests.`,

  containment: {
    isolateDevice: true,
    disableAccount: false,
    revokeSession: false,
  },
};
