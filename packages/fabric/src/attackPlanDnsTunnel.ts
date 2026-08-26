import type {
  AttackPlan,
} from "./attackPlan.js";

/** Algorithmically-generated beacon domains: high-entropy label, throwaway TLD. */
const DGA_DOMAINS = [
  "kq3n9x2p4m8t.info",
  "z7b1r5w0c6vh.info",
  "j2m8k4x9q1np.top",
  "p5t0n3z8b2rk.top",
];

/** The long, base32-looking name that carries tunnelled data out over DNS. */
const EXFIL_NAME =
  "mfrggzdfmztwq2lknnwg23tpobyxe43uonzwq43fmruw4zzanvxxezjanv2q.tunnel-x7.info";

/**
 * DNS command-and-control and data tunnelling.
 *
 * DNS is a blind spot for a host-and-identity investigation: nothing runs on an
 * endpoint that a process view would flag, no sign-in is anomalous, and the
 * traffic is port-53 lookups that every machine makes constantly. The intrusion
 * is only visible in the resolver log, a beacon resolving a rotating set of
 * algorithmically-generated domains, then data leaving the network encoded into
 * the names of TXT queries no application would ever make.
 *
 * The lesson is that DNS analytics read the *name*, not the fact of a query.
 * The beacon hides among tens of thousands of benign lookups; what separates it
 * is the shape of what it asks for, random high-entropy labels on throwaway
 * TLDs, and query names far longer than any real hostname.
 */
export const DNS_TUNNEL_PLAN: AttackPlan =
  {
    id: "dns-tunnel",
    name: "DNS command-and-control and tunnelled exfiltration",
    difficulty: "advanced",
    lesson:
      "This intrusion is invisible to every console except the resolver log: no process is anomalous, no sign-in is out of place, and the traffic is ordinary port-53 lookups. What betrays it is the shape of the names, a beacon resolving rotating high-entropy domains on throwaway TLDs, and data leaving encoded into TXT query names far longer than any real hostname. A rule that alerts on 'a DNS query' drowns in tens of thousands of benign lookups; one that reads the entropy and the length of the name does not.",
    requires: {},

    techniques: [
      {
        id: "T1568.002",
        name: "Dynamic Resolution: Domain Generation Algorithms",
        tactic: "command_and_control",
      },
      {
        id: "T1071.004",
        name: "Application Layer Protocol: DNS",
        tactic: "command_and_control",
      },
      {
        id: "T1048.003",
        name: "Exfiltration Over Alternative Protocol: Unencrypted Non-C2",
        tactic: "exfiltration",
      },
    ],

    steps: [
      {
        id: "dga-resolve",
        title:
          "A host resolves a rotating set of algorithmic domains",
        techniqueId: "T1568.002",
        repeat: 4,
        advanceBy: 5,
        significance: (cast) =>
          `${cast.subjectDevice.hostname} resolved a sequence of random-looking domains on throwaway TLDs, the fingerprint of a domain-generation algorithm cycling rendezvous points.`,
        reasoning: () =>
          "A single one of these looks like a typo or a tracker; the pattern is the signal. Human and application DNS resolves pronounceable, registered names; a domain-generation algorithm resolves high-entropy strings on cheap TLDs, a new one each interval, so that blocking any single domain does nothing. Read the query names as a set, not one at a time, and pivot on the requesting host, the value here is identifying the beacon, not the individual domains, which are disposable by design.",
        build: (cast, index) => ({
          type: "DNS_QUERY",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            queryName:
              DGA_DOMAINS[
                index % DGA_DOMAINS.length
              ],
            queryType: "A",
            sourceIp: cast.subjectIp,
          },
        }),
      },
      {
        id: "dns-c2",
        title:
          "The beacon settles on one control domain",
        techniqueId: "T1071.004",
        repeat: 3,
        advanceBy: 6,
        significance: (cast) =>
          `Regular TXT lookups to a single control domain from ${cast.subjectDevice.hostname}, at a steady interval, command-and-control carried inside DNS rather than over a web connection.`,
        reasoning: () =>
          "Once a generated domain resolves, the beacon uses it as a channel: DNS is allowed outbound almost everywhere, so C2 tunnelled through it bypasses the web proxy entirely. The regularity is the tell, the same as any beacon, a fixed cadence means software, not a person. Establish the interval and the control domain, then treat every host querying it as part of the same intrusion.",
        build: (cast) => ({
          type: "DNS_QUERY",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            queryName: "cmd.tunnel-x7.info",
            queryType: "TXT",
            sourceIp: cast.subjectIp,
          },
        }),
      },
      {
        id: "dns-exfil",
        title:
          "Data leaves encoded in a DNS query name",
        techniqueId: "T1048.003",
        advanceBy: 3,
        significance: (cast) =>
          `A single enormous TXT query from ${cast.subjectDevice.hostname} whose name is an encoded blob far longer than any real hostname, data being carried out of the network inside the question itself.`,
        reasoning: () =>
          "This is the exfiltration, and unlike a file copy it never opens a connection to anything a proxy or firewall inspects, the payload rides out inside the DNS question, which the resolver dutifully forwards. The signal is the name: real hostnames are short and pronounceable, and a base32 label pushing the length limit is not a lookup, it is a transfer. Measure the volume of data that could have left by the size and count of these, and treat the encoded content as the scope of the loss.",
        build: (cast) => ({
          type: "DNS_QUERY",
          source: "network",
          subjectId: cast.subjectDevice.id,
          payload: {
            deviceId: cast.subjectDevice.id,
            queryName: EXFIL_NAME,
            queryType: "TXT",
            sourceIp: cast.subjectIp,
          },
        }),
      },
    ],

    questions: [
      {
        id: "q-host",
        prompt: () =>
          "Which host was beaconing over DNS?",
        accepted: (cast) => [
          cast.subjectDevice.hostname,
          cast.subjectDevice.id,
        ],
        hint: "Look for a host resolving many high-entropy domains on throwaway TLDs.",
        surface: "siem",
        points: 25,
        evidenceStepId: "dga-resolve",
      },
      {
        id: "q-control",
        prompt: () =>
          "Which control domain did the beacon settle on?",
        accepted: () => [
          "cmd.tunnel-x7.info",
          "tunnel-x7.info",
        ],
        hint: "Repeated TXT lookups to one domain at a steady interval.",
        surface: "siem",
        points: 25,
        evidenceStepId: "dns-c2",
      },
      {
        id: "q-exfil",
        prompt: () =>
          "What record type carried the exfiltrated data?",
        accepted: () => ["TXT", "txt"],
        hint: "The query name was an encoded blob far longer than any real hostname.",
        surface: "siem",
        points: 25,
        evidenceStepId: "dns-exfil",
      },
      {
        id: "q-dga",
        prompt: () =>
          "Name one of the algorithmically-generated domains the beacon resolved.",
        accepted: () => [
          "kq3n9x2p4m8t.info",
          "z7b1r5w0c6vh.info",
          "j2m8k4x9q1np.top",
          "p5t0n3z8b2rk.top",
        ],
        hint: "High-entropy labels on throwaway TLDs, resolved in sequence.",
        surface: "siem",
        points: 25,
        evidenceStepId: "dga-resolve",
      },
    ],

    alertTitle: () =>
      `DNS beaconing and tunnelled exfiltration detected`,
    alertSeverity: "high",
    alertStepIds: ["dns-exfil"],

    summary: (cast) =>
      `${cast.subjectDevice.hostname} ran a DNS beacon: it resolved a rotating set of algorithmically-generated domains on throwaway TLDs, settled on the control domain tunnel-x7.info for command-and-control carried inside TXT lookups, and then exfiltrated data encoded into an enormous TXT query name. No process was anomalous and no sign-in was out of place; the entire intrusion is visible only in the resolver log, in the shape of the names queried.`,

    containment: {
      isolateDevice: true,
      disableAccount: false,
      revokeSession: false,
    },
  };
