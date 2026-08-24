/**
 * Reputation for the adversary infrastructure the generator plants.
 *
 * An external address is flagged external everywhere in the product, but
 * "external" is where a real analyst's question starts, not where it ends: a
 * sign-in from a residential ISP and one from a Tor exit are both external and
 * mean very different things. A SOC answers that with threat intelligence, and
 * the generator is the one place that can answer it truthfully -- it chose the
 * address, so it knows what the address is meant to represent, rather than
 * guessing from the octets.
 *
 * The classification is deterministic and closed: it covers exactly the
 * addresses the attack-plan library draws its infrastructure from. A benign
 * corporate or residential address is absent by design, so the enrichment
 * only ever speaks about the addresses it actually knows something about.
 */
export type ThreatCategory =
  | "tor-exit"
  | "bulletproof-hosting"
  | "anonymizing-vpn"
  | "hosting-provider";

export interface ThreatIntelEntry {
  readonly indicator: string;

  readonly category: ThreatCategory;

  /** Human-readable reason, shown in tooling rather than inferred again. */
  readonly note: string;
}

const CLASSIFICATION: Readonly<
  Record<
    string,
    {
      readonly category: ThreatCategory;
      readonly note: string;
    }
  >
> = {
  "185.220.101.44": {
    category: "tor-exit",
    note: "Known Tor exit relay. Traffic leaving it is anonymised by design, and a corporate account has no ordinary reason to authenticate through one.",
  },
  "185.220.101.79": {
    category: "tor-exit",
    note: "Known Tor exit relay, in the same range as the initial-access address. Reuse of the anonymising network for command and control is common.",
  },
  "45.153.160.132": {
    category: "bulletproof-hosting",
    note: "Assigned to a hosting provider that ignores abuse complaints, repeatedly named in credential-attack and malware campaigns.",
  },
  "45.153.160.208": {
    category: "bulletproof-hosting",
    note: "Same abuse-tolerant hosting range as the access address. Short-lived infrastructure on such providers is a hallmark of hands-on intrusion.",
  },
  "193.32.127.201": {
    category: "anonymizing-vpn",
    note: "Egress address of a commercial VPN service. It hides the true origin and is shared by many unrelated users, so the sign-in cannot be tied to a place.",
  },
  "91.219.236.18": {
    category: "hosting-provider",
    note: "Datacenter address of a virtual-server provider. Interactive sign-ins to a staff account rarely originate from a hosting network rather than a home or office one.",
  },
};

/**
 * Classifies the addresses that appear in an incident against the closed set
 * of known adversary infrastructure, returning one entry per distinct address
 * that is recognised. Order is stable for a deterministic file.
 */
export function classifyIndicators(
  addresses: Iterable<string>,
): ThreatIntelEntry[] {
  const seen = new Set<string>();
  const entries: ThreatIntelEntry[] = [];

  for (const address of addresses) {
    if (seen.has(address)) {
      continue;
    }

    seen.add(address);

    const match = CLASSIFICATION[address];

    if (match) {
      entries.push({
        indicator: address,
        category: match.category,
        note: match.note,
      });
    }
  }

  entries.sort((left, right) =>
    left.indicator.localeCompare(
      right.indicator,
    ),
  );

  return entries;
}
