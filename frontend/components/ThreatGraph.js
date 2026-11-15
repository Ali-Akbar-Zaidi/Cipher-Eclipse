"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { buildGraph, NODE_H, NODE_W } from "@/lib/graph";
import { KIND_STYLE, SEVERITY_STYLE } from "@/lib/format";

function styleFor(data) {
  if (data.kind === "cve") return { ...SEVERITY_STYLE[data.severity || "NONE"], tag: data.severity === "NONE" ? "CVE" : data.severity };
  return KIND_STYLE[data.kind];
}

function EntityNode({ data, selected }) {
  const s = styleFor(data);
  const critical = data.kind === "cve" && (data.severity === "CRITICAL" || data.severity === "HIGH");
  return (
    <div
      className="rounded-md border px-2.5 py-1.5 text-left transition-shadow"
      style={{
        width: NODE_W,
        height: NODE_H,
        background: s.fill,
        borderColor: s.border,
        color: s.text,
        borderStyle: data.kind === "cdn" ? "dashed" : "solid",
        boxShadow: selected
          ? `0 0 0 2px #f5a524, 0 0 18px ${s.border}66`
          : critical
            ? `0 0 12px ${s.border}40`
            : "none",
      }}
      title={`${data.label} — ${data.sub}`}
    >
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-zinc-500" />
      <div className="flex items-center gap-1.5">
        <span className="rounded px-1 text-[9px] font-semibold uppercase tracking-wider" style={{ background: `${s.border}33`, color: s.border }}>
          {s.tag}
        </span>
        {data.kevLikely && (
          <span className="rounded bg-red-500 px-1 text-[9px] font-bold uppercase tracking-wider text-white" title="Model estimates ≥10% chance this CVE is in CISA KEV">
            KEV-likely
          </span>
        )}
      </div>
      <div className="truncate font-mono text-[12px] font-medium leading-tight">{data.label}</div>
      <div className="truncate text-[10px] opacity-75">{data.sub}</div>
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-zinc-500" />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

function minimapColor(n) {
  return styleFor(n.data).border;
}

function Graph({ scan, selectedId, onSelect, options }) {
  const { nodes, edges } = useMemo(() => buildGraph(scan, options), [scan, options]);
  const { setCenter, fitView } = useReactFlow();

  const styledEdges = useMemo(
    () =>
      edges.map((e) => {
        const active = selectedId && (e.source === selectedId || e.target === selectedId);
        return {
          ...e,
          animated: Boolean(active),
          style: {
            stroke: active ? "#f5a524" : e.data?.hot ? "#b91c1c" : "#3a4052",
            strokeWidth: active ? 2 : e.data?.hot ? 1.4 : 1,
          },
        };
      }),
    [edges, selectedId],
  );
  const styledNodes = useMemo(() => nodes.map((n) => ({ ...n, selected: n.id === selectedId })), [nodes, selectedId]);

  useEffect(() => {
    const n = nodes.find((x) => x.id === selectedId);
    if (n) setCenter(n.position.x + NODE_W / 2, n.position.y + NODE_H / 2, { zoom: 1.1, duration: 450 });
  }, [selectedId, nodes, setCenter]);

  useEffect(() => {
    const t = setTimeout(() => fitView({ padding: 0.08, duration: 300 }), 30);
    return () => clearTimeout(t);
  }, [nodes, fitView]);

  return (
    <ReactFlow
      nodes={styledNodes}
      edges={styledEdges}
      nodeTypes={nodeTypes}
      onNodeClick={(_, n) => onSelect(n.id)}
      onPaneClick={() => onSelect(null)}
      nodesConnectable={false}
      nodesDraggable
      minZoom={0.05}
      maxZoom={2}
      // Plain wheel scrolls the page; Ctrl/Cmd + wheel (or pinch) zooms the graph.
      zoomOnScroll={false}
      preventScrolling={false}
      zoomActivationKeyCode={["Control", "Meta"]}
      fitView
      proOptions={{ hideAttribution: true }}
      colorMode="dark"
    >
      <Background color="#262b38" gap={22} size={1} />
      <Controls showInteractive={false} />
      <MiniMap pannable zoomable nodeColor={minimapColor} maskColor="rgba(8,10,14,0.75)" style={{ background: "#0d1016" }} />
    </ReactFlow>
  );
}

const PER_SERVICE = [
  { label: "Top 5", value: 5 },
  { label: "Top 10", value: 10 },
  { label: "Top 25", value: 25 },
  { label: "All", value: Infinity },
];
const MIN_RISK = [0, 25, 50, 75];

export default function ThreatGraph({ scan, selectedId, onSelect }) {
  const [perService, setPerService] = useState(10);
  const [minRisk, setMinRisk] = useState(0);
  const options = useMemo(() => ({ cvesPerService: perService, minRisk }), [perService, minRisk]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-[var(--line)] px-4 py-2.5 text-xs">
        <h2 className="text-sm font-semibold text-zinc-100">Threat graph</h2>
        <span className="mr-auto hidden text-[11px] text-zinc-500 sm:inline">Drag to pan · Ctrl + scroll to zoom</span>
        <label className="flex items-center gap-1.5 text-zinc-400">
          CVEs per service
          <select className="ce-select" value={String(perService)} onChange={(e) => setPerService(e.target.value === "Infinity" ? Infinity : Number(e.target.value))}>
            {PER_SERVICE.map((o) => (
              <option key={o.label} value={String(o.value)}>{o.label}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-zinc-400">
          Min risk
          <select className="ce-select" value={minRisk} onChange={(e) => setMinRisk(Number(e.target.value))}>
            {MIN_RISK.map((r) => (
              <option key={r} value={r}>{r === 0 ? "Any" : `≥ ${r}`}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="relative min-h-0 flex-1">
        <ReactFlowProvider>
          <Graph scan={scan} selectedId={selectedId} onSelect={onSelect} options={options} />
        </ReactFlowProvider>
        <Legend />
      </div>
    </div>
  );
}

function Legend() {
  const items = [
    ["Domain", KIND_STYLE.domain.border],
    ["Subdomain", KIND_STYLE.subdomain.border],
    ["IP", KIND_STYLE.ip.border],
    ["Origin hidden (CDN)", KIND_STYLE.cdn.border],
    ["Service (CPE)", KIND_STYLE.service.border],
    ["Critical CVE", SEVERITY_STYLE.CRITICAL.border],
    ["High CVE", SEVERITY_STYLE.HIGH.fill],
    ["Medium CVE", SEVERITY_STYLE.MEDIUM.border],
    ["Low CVE", SEVERITY_STYLE.LOW.border],
  ];
  return (
    <div className="pointer-events-none absolute left-3 top-3 hidden flex-col gap-1 rounded-md border border-[var(--line)] bg-[#0d1016]/90 p-2 text-[10px] text-zinc-400 md:flex">
      {items.map(([label, color]) => (
        <div key={label} className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: color }} />
          {label}
        </div>
      ))}
    </div>
  );
}
