"use client";

import { useMemo, useState } from "react";
import { fmtNum, fmtPct, riskTier, SEVERITY_ORDER, SEVERITY_STYLE, severityOf } from "@/lib/format";

function SortHeader({ label, k, sort, setSort, align = "left", title }) {
  const active = sort.key === k;
  return (
    <th className={`px-3 py-2 font-medium ${align === "right" ? "text-right" : "text-left"}`} title={title}>
      <button
        type="button"
        onClick={() => setSort((s) => ({ key: k, dir: s.key === k && s.dir === "desc" ? "asc" : "desc" }))}
        className={`inline-flex items-center gap-1 hover:text-zinc-100 ${active ? "text-amber-300" : ""}`}
        aria-sort={active ? (sort.dir === "desc" ? "descending" : "ascending") : "none"}
      >
        {label}
        <span className="text-[9px]">{active ? (sort.dir === "desc" ? "▼" : "▲") : "↕"}</span>
      </button>
    </th>
  );
}

function sortRows(rows, { key, dir }, get) {
  const sign = dir === "desc" ? -1 : 1;
  return [...rows].sort((a, b) => {
    const x = get(a, key);
    const y = get(b, key);
    // missing values always sink to the bottom, whatever the direction
    if (x == null && y == null) return 0;
    if (x == null) return 1;
    if (y == null) return -1;
    if (typeof x === "string") return sign * x.localeCompare(y);
    return sign * (x - y);
  });
}

export function SeverityBadge({ severity }) {
  const s = SEVERITY_STYLE[severity] || SEVERITY_STYLE.NONE;
  return <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ${s.badge}`}>{severity === "NONE" ? "n/a" : severity}</span>;
}

export function RiskBar({ value }) {
  const tier = riskTier(value);
  const color = SEVERITY_STYLE[tier].border;
  return (
    <div className="flex items-center justify-end gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded bg-zinc-800">
        <div className="h-full rounded" style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%`, background: color }} />
      </div>
      <span className="w-8 text-right font-mono tabular-nums">{value == null ? "—" : Math.round(value)}</span>
    </div>
  );
}

function VulnTable({ scan, query, onSelect, selectedId }) {
  const [sort, setSort] = useState({ key: "risk_score", dir: "desc" });
  const hostSubs = useMemo(() => new Map((scan.hosts || []).map((h) => [h.ip, h.subdomains || []])), [scan]);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = (scan.vulnerabilities || []).filter((v) => {
      if (!q) return true;
      const hay = [v.cve_id, v.description, ...(v.hosts || []), ...(v.hosts || []).flatMap((ip) => hostSubs.get(ip) || [])].join(" ").toLowerCase();
      return hay.includes(q);
    });
    return sortRows(filtered, sort, (v, k) => (k === "severity" ? SEVERITY_ORDER[severityOf(v)] : v[k]));
  }, [scan, query, sort, hostSubs]);

  return (
    <table className="w-full min-w-[860px] text-sm">
      <thead className="sticky top-0 z-10 bg-[#11141b] text-xs text-zinc-400">
        <tr className="border-b border-[var(--line)]">
          <SortHeader label="CVE" k="cve_id" sort={sort} setSort={setSort} />
          <SortHeader label="Severity" k="severity" sort={sort} setSort={setSort} />
          <SortHeader label="Risk score" k="risk_score" sort={sort} setSort={setSort} align="right" title="0-100 Risk Priority Score (CVSS, EPSS, exposure and the KEV model)" />
          <SortHeader label="CVSS" k="cvss_score" sort={sort} setSort={setSort} align="right" />
          <SortHeader label="EPSS" k="epss_score" sort={sort} setSort={setSort} align="right" title="Probability of exploitation in the next 30 days (FIRST EPSS)" />
          <SortHeader label="KEV prob." k="kev_probability" sort={sort} setSort={setSort} align="right" title="Classifier estimate that the CVE is in CISA KEV" />
          <th className="px-3 py-2 text-left font-medium">Affected hosts</th>
          <th className="px-3 py-2 text-left font-medium">Notes</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((v) => {
          const id = `c:${v.cve_id}`;
          return (
            <tr
              key={v.cve_id}
              onClick={() => onSelect(id)}
              className={`cursor-pointer border-b border-[var(--line)]/60 hover:bg-white/[0.03] ${selectedId === id ? "bg-amber-400/[0.07]" : ""}`}
            >
              <td className="px-3 py-2 font-mono text-[13px] text-zinc-100">
                <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()} className="hover:text-amber-300 hover:underline">
                  {v.cve_id}
                </a>
              </td>
              <td className="px-3 py-2"><SeverityBadge severity={severityOf(v)} /></td>
              <td className="px-3 py-2"><RiskBar value={v.risk_score} /></td>
              <td className="px-3 py-2 text-right font-mono tabular-nums">{fmtNum(v.cvss_score)}</td>
              <td className="px-3 py-2 text-right font-mono tabular-nums">{fmtPct(v.epss_score, 2)}</td>
              <td className="px-3 py-2 text-right font-mono tabular-nums">{fmtPct(v.kev_probability, 1)}</td>
              <td className="max-w-[220px] px-3 py-2 text-xs text-zinc-300">
                {(v.hosts || []).map((ip) => (
                  <div key={ip} className="truncate" title={(hostSubs.get(ip) || []).join(", ")}>
                    <span className="font-mono">{ip}</span>
                    {hostSubs.get(ip)?.length ? <span className="text-zinc-500"> · {hostSubs.get(ip)[0]}{hostSubs.get(ip).length > 1 ? ` +${hostSubs.get(ip).length - 1}` : ""}</span> : null}
                  </div>
                ))}
              </td>
              <td className="px-3 py-2 text-[11px] text-zinc-400">
                <span className="mr-1 rounded bg-zinc-800 px-1.5 py-0.5" title="Matched from software version by Shodan InternetDB; not confirmed">potential</span>
                {v.backport_suspect && <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-amber-300/80" title="Distribution package: the fix may be back-ported">backport?</span>}
                {!v.in_vulndb && <span className="rounded bg-zinc-800 px-1.5 py-0.5">not in NVD cache</span>}
              </td>
            </tr>
          );
        })}
        {!rows.length && (
          <tr><td colSpan={8} className="px-3 py-10 text-center text-zinc-500">No vulnerabilities match.</td></tr>
        )}
      </tbody>
    </table>
  );
}

function AssetTable({ scan, query, onSelect, selectedId }) {
  const [sort, setSort] = useState({ key: "max_risk", dir: "desc" });
  const hostByIp = useMemo(() => new Map((scan.hosts || []).map((h) => [h.ip, h])), [scan]);
  const rows = useMemo(() => {
    const flat = (scan.subdomains || []).flatMap((s) =>
      s.ips.map((ip) => {
        const h = hostByIp.get(ip) || {};
        return {
          key: `${s.name}|${ip}`,
          subdomain: s.name,
          ip,
          status: h.origin_hidden ? `CDN (${h.cdn})` : h.internetdb ? "Scanned" : "No data",
          ports: h.ports || [],
          port_count: (h.ports || []).length,
          cve_count: (h.cves || []).length,
          max_risk: h.max_risk ?? null,
          cpes: h.cpes || [],
          origin_hidden: h.origin_hidden,
        };
      }),
    );
    const q = query.trim().toLowerCase();
    const filtered = q ? flat.filter((r) => [r.subdomain, r.ip, r.status, ...r.cpes].join(" ").toLowerCase().includes(q)) : flat;
    return sortRows(filtered, sort, (r, k) => r[k]);
  }, [scan, query, sort, hostByIp]);

  return (
    <table className="w-full min-w-[820px] text-sm">
      <thead className="sticky top-0 z-10 bg-[#11141b] text-xs text-zinc-400">
        <tr className="border-b border-[var(--line)]">
          <SortHeader label="Subdomain" k="subdomain" sort={sort} setSort={setSort} />
          <SortHeader label="IP" k="ip" sort={sort} setSort={setSort} />
          <SortHeader label="Status" k="status" sort={sort} setSort={setSort} />
          <SortHeader label="Ports" k="port_count" sort={sort} setSort={setSort} />
          <th className="px-3 py-2 text-left font-medium">Software (CPE)</th>
          <SortHeader label="CVEs" k="cve_count" sort={sort} setSort={setSort} align="right" />
          <SortHeader label="Max risk" k="max_risk" sort={sort} setSort={setSort} align="right" />
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const id = `i:${r.ip}`;
          return (
            <tr key={r.key} onClick={() => onSelect(id)} className={`cursor-pointer border-b border-[var(--line)]/60 hover:bg-white/[0.03] ${selectedId === id ? "bg-amber-400/[0.07]" : ""}`}>
              <td className="px-3 py-2 font-mono text-[13px] text-zinc-100">{r.subdomain}</td>
              <td className="px-3 py-2 font-mono text-[13px]">{r.ip}</td>
              <td className="px-3 py-2 text-xs">
                <span className={`rounded px-1.5 py-0.5 ${r.origin_hidden ? "bg-zinc-800 text-zinc-400" : r.status === "Scanned" ? "bg-teal-950 text-teal-300" : "bg-zinc-900 text-zinc-500"}`}>{r.origin_hidden ? "Origin hidden" : r.status}</span>
              </td>
              <td className="px-3 py-2 font-mono text-xs text-zinc-300">{r.ports.join(", ") || "—"}</td>
              <td className="max-w-[260px] truncate px-3 py-2 font-mono text-[11px] text-zinc-400" title={r.cpes.join("\n")}>{r.cpes.map((c) => c.replace(/^cpe:\/[aho]:/, "")).join(", ") || "—"}</td>
              <td className="px-3 py-2 text-right font-mono tabular-nums">{r.cve_count}</td>
              <td className="px-3 py-2"><RiskBar value={r.max_risk} /></td>
            </tr>
          );
        })}
        {!rows.length && (
          <tr><td colSpan={7} className="px-3 py-10 text-center text-zinc-500">No assets match.</td></tr>
        )}
      </tbody>
    </table>
  );
}

export default function DataTables({ scan, onSelect, selectedId }) {
  const [tab, setTab] = useState("vulns");
  const [query, setQuery] = useState("");
  const tabs = [
    ["vulns", `Vulnerabilities (${scan.vulnerabilities?.length ?? 0})`],
    ["assets", `Assets (${(scan.subdomains || []).reduce((n, s) => n + s.ips.length, 0)})`],
  ];
  return (
    <section className="ce-panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] px-3 py-2">
        <div role="tablist" className="flex gap-1">
          {tabs.map(([k, label]) => (
            <button
              key={k}
              role="tab"
              aria-selected={tab === k}
              onClick={() => setTab(k)}
              className={`rounded px-3 py-1.5 text-sm ${tab === k ? "bg-white/[0.07] text-zinc-100" : "text-zinc-400 hover:text-zinc-200"}`}
            >
              {label}
            </button>
          ))}
        </div>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={tab === "vulns" ? "Filter by CVE, host or keyword" : "Filter by subdomain, IP or software"}
          className="ce-input ml-auto w-full sm:w-72"
        />
      </div>
      <div className="max-h-[560px] overflow-auto">
        {tab === "vulns" ? <VulnTable scan={scan} query={query} onSelect={onSelect} selectedId={selectedId} /> : <AssetTable scan={scan} query={query} onSelect={onSelect} selectedId={selectedId} />}
      </div>
    </section>
  );
}
