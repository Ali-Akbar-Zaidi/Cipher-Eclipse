"use client";

import { SeverityBadge } from "./DataTables";

const PRIORITY_LABEL = { immediate: "Immediate", short_term: "Short term", long_term: "Long term" };
const PRIORITY_STYLE = {
  immediate: "bg-red-950 text-red-200 ring-red-500/50",
  short_term: "bg-amber-950 text-amber-200 ring-amber-500/40",
  long_term: "bg-zinc-800 text-zinc-300 ring-zinc-500/40",
};

function Entities({ item, onSelect }) {
  const chips = [
    ...(item.cve_ids || []).map((x) => ["c:" + x, x]),
    ...(item.ips || []).map((x) => ["i:" + x, x]),
    ...(item.hosts || []).map((x) => ["s:" + x, x]),
  ];
  if (!chips.length) return null;
  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      {chips.map(([id, label]) => (
        <button key={id} type="button" onClick={() => onSelect(id)} className="rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-[11px] text-zinc-300 hover:bg-amber-400/15 hover:text-amber-200">
          {label}
        </button>
      ))}
    </div>
  );
}

function ValidationBadge({ summary }) {
  const v = summary.validation || {};
  const llm = summary.llm_validation;
  let text;
  let tone;
  if (summary.generator === "llm") {
    const removed = v.unknown_entities?.length || 0;
    tone = removed ? "text-amber-300 ring-amber-500/40" : "text-emerald-300 ring-emerald-500/40";
    text = removed
      ? `Verified: ${removed} ungrounded ${removed === 1 ? "mention" : "mentions"} removed (${v.entities_checked} checked)`
      : `Verified: all ${v.entities_checked} cited entities found in scan data`;
  } else {
    tone = "text-zinc-300 ring-zinc-500/40";
    text = llm?.status === "rejected" ? "LLM output rejected by hallucination check; showing data-derived summary" : "Data-derived summary (no LLM)";
  }
  return <span className={`rounded px-2 py-0.5 text-[11px] ring-1 ${tone}`} title={summary.note || ""}>{text}</span>;
}

export default function SummaryPanel({ summary, onSelect }) {
  if (!summary) return null;
  if (summary.generator === "none") {
    return <section className="ce-panel p-5 text-sm text-zinc-400">Summary unavailable.</section>;
  }
  return (
    <section className="ce-panel p-5">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Executive summary</h2>
        <SeverityBadge severity={(summary.overall_risk || "none").toUpperCase() === "INFORMATIONAL" ? "NONE" : (summary.overall_risk || "NONE").toUpperCase()} />
        <span className="ml-auto flex flex-wrap items-center gap-2 text-[11px] text-zinc-500">
          {summary.generator === "llm" && summary.model ? <span className="font-mono">{summary.model}</span> : null}
          <ValidationBadge summary={summary} />
        </span>
      </div>
      <p className="mt-3 text-lg font-medium text-zinc-100 text-balance">{summary.headline}</p>
      <p className="mt-2 max-w-4xl text-sm leading-relaxed text-zinc-300">{summary.executive_summary}</p>

      <div className="mt-5 grid gap-6 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">Key findings</h3>
          <ol className="space-y-3">
            {(summary.key_findings || []).map((f, i) => (
              <li key={i} className="rounded-md border border-[var(--line)] bg-black/20 p-3">
                <div className="flex items-start gap-2">
                  <SeverityBadge severity={f.severity === "informational" ? "NONE" : f.severity.toUpperCase()} />
                  <span className="text-sm font-medium text-zinc-100">{f.title}</span>
                </div>
                <p className="mt-1 text-[13px] leading-relaxed text-zinc-400">{f.detail}</p>
                <Entities item={f} onSelect={onSelect} />
              </li>
            ))}
          </ol>
        </div>
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">Recommendations</h3>
          <ol className="space-y-3">
            {(summary.recommendations || []).map((r, i) => (
              <li key={i} className="rounded-md border border-[var(--line)] bg-black/20 p-3">
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ${PRIORITY_STYLE[r.priority]}`}>{PRIORITY_LABEL[r.priority]}</span>
                <p className="mt-1.5 text-[13px] leading-relaxed text-zinc-300">{r.action}</p>
                <Entities item={r} onSelect={onSelect} />
              </li>
            ))}
          </ol>
          {summary.limitations?.length ? (
            <>
              <h3 className="mb-2 mt-5 text-xs font-semibold uppercase tracking-wider text-zinc-500">Limitations</h3>
              <ul className="list-disc space-y-1 pl-5 text-[12px] text-zinc-500">
                {summary.limitations.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}
