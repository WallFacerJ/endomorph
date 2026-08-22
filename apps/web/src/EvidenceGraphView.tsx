import type {
  EvidenceGraph,
  EvidenceGraphNode,
} from "./simulationAdapter";

import {
  Icon,
} from "./Icon";

import type {
  IconName,
} from "./Icon";

import "./EvidenceGraphView.css";

/**
 * The evidence graph, drawn as a graph.
 *
 * It was a list of entities followed by a list of pairs, which is the same
 * information and none of the value: the point of a graph is that a shape
 * carries the relationships, and a reader asked to hold twelve pairs in
 * their head to see that shape is doing the drawing themselves.
 *
 * The layout is deterministic -- entities are placed by kind around a ring,
 * ordered as the graph delivers them. No force simulation. That is partly
 * this product's whole premise, and partly practical: a physics layout
 * settles somewhere slightly different on every render, so an analyst who
 * looked away would come back to a different picture of the same evidence,
 * and two people comparing screens would disagree about what they saw.
 */

const KIND_ICONS: Readonly<
  Record<string, IconName>
> = {
  user: "user",
  account: "identity",
  device: "endpoint",
  address: "network",
  file: "file",
  process: "process",
  application: "server",
};

/** Ring order, so the same kinds sit together and the graph reads by sector. */
const KIND_ORDER: readonly string[] = [
  "user",
  "account",
  "device",
  "process",
  "file",
  "application",
  "address",
];

interface EvidenceGraphViewProps {
  readonly graph: EvidenceGraph;
  readonly selectedId?: string;
  readonly onSelect: (
    node: EvidenceGraphNode,
  ) => void;
}

export function EvidenceGraphView({
  graph,
  selectedId,
  onSelect,
}: EvidenceGraphViewProps) {
  const nodes = [...graph.nodes].sort(
    (left, right) => {
      const byKind =
        KIND_ORDER.indexOf(left.kind) -
        KIND_ORDER.indexOf(right.kind);

      return byKind !== 0
        ? byKind
        : left.label.localeCompare(
            right.label,
          );
    },
  );

  if (nodes.length === 0) {
    return null;
  }

  const size = 320;
  const centre = size / 2;

  // A single node has no ring to sit on; anything more spreads evenly.
  const radius =
    nodes.length === 1
      ? 0
      : size / 2 - 46;

  const positions = new Map<
    string,
    { x: number; y: number }
  >();

  nodes.forEach((node, index) => {
    // Start at the top and go clockwise, so the first kind in the order is
    // always in the same place regardless of how many nodes there are.
    const angle =
      (index / nodes.length) *
        Math.PI *
        2 -
      Math.PI / 2;

    positions.set(node.id, {
      x:
        centre +
        Math.cos(angle) * radius,
      y:
        centre +
        Math.sin(angle) * radius,
    });
  });

  return (
    <div className="evidence-graph">
      <svg
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label={`Evidence graph: ${nodes.length} entities, ${graph.edges.length} relationships`}
      >
        <g className="evidence-edges">
          {graph.edges.map((edge) => {
            const from = positions.get(
              edge.from,
            );

            const to = positions.get(
              edge.to,
            );

            if (!from || !to) {
              return null;
            }

            const touchesSelected =
              selectedId === edge.from ||
              selectedId === edge.to;

            return (
              <line
                key={`${edge.from}-${edge.to}`}
                className={
                  touchesSelected
                    ? "evidence-edge active"
                    : "evidence-edge"
                }
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                // Thicker where more collected events tie the pair together.
                strokeWidth={Math.min(
                  3,
                  1 +
                    edge.eventIds.length *
                      0.4,
                )}
              />
            );
          })}
        </g>

        {nodes.map((node) => {
          const at = positions.get(
            node.id,
          );

          if (!at) {
            return null;
          }

          return (
            <g
              key={node.id}
              className={[
                "evidence-node",
                node.external
                  ? "external"
                  : "",
                selectedId === node.id
                  ? "selected"
                  : "",
              ]
                .filter(Boolean)
                .join(" ")}
              transform={`translate(${at.x} ${at.y})`}
            >
              <circle
                r={
                  8 +
                  Math.min(
                    5,
                    node.eventIds.length,
                  )
                }
              />
            </g>
          );
        })}
      </svg>

      {/*
        The labels are HTML rather than SVG text: they need to wrap, ellipsis
        and be clickable targets of a reasonable size, all of which SVG text
        makes hard and none of which it does better.
      */}
      <ul className="evidence-legend">
        {nodes.map((node) => (
          <li key={node.id}>
            <button
              type="button"
              className={
                selectedId === node.id
                  ? "evidence-chip selected"
                  : "evidence-chip"
              }
              onClick={() =>
                onSelect(node)
              }
              title={`${node.label} — ${node.eventIds.length} collected event(s)`}
            >
              <Icon
                name={
                  KIND_ICONS[node.kind] ??
                  "pin"
                }
                size={13}
              />

              <span className="evidence-chip-label">
                {node.label}
              </span>

              {node.external && (
                <span className="evidence-external">
                  external
                </span>
              )}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
