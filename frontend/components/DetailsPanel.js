"use client";

import { fmtNum, fmtPct, PORT_NAMES, severityOf } from "@/lib/format";
import { RiskBar, SeverityBadge } from "./DataTables";

function Row({ label, children }) {
  return (
    <div className="flex justify-between gap-3 border-b border-[var(--line)]/60 py-1.5 text-[13px]">
      <span className="shrink-0 text-zinc-500">{label}</span>
      <span className="min-w-0 text-right text-zinc-200">{children}</span>
    </div>
  );
}

function List({ items, mono = true, onPick }) {
  if (!items?.length) return <span className="text-zinc-500">—</span>;
  return (
    <div className="flex flex-wrap justify-end gap-1">
      {items.map(([id, label]) =>
        onPick && id ? (
          <button key={label} type="button" onClick={() => onPick(id)} className={`rounded bg-white/[0.05] px-1.5 py-0.5 text-[11px] hover:bg-amber-400/15 hover:text-amber-200 ${mono ? "font-mono" : ""}`}>{label}</button>
        ) : (
          <span key={label} className={`rounded bg-white/[0.05] px-1.5 py-0.5 text-[11px] ${mono ? "font-mono" : ""}`}>{label}</span>
        ),
      )}
    </div>
  );
}

export default function DetailsPanel({ scan, selectedId, onSelect }) {
  if (!selectedId) {
    return (
      <div className="p-5 text-sm text-zinc-500">
        <p className="font-medium text-zinc-300">Select a node</p>
        <p className="mt-1">Click any node in the graph, a row in the tables or an entity in the summary to see its details here.</p>
      </div>
    );
  }
  const [kind, ...rest] = selectedId.split(":");
  const ref = rest.join(":");

  if (kind === "c") {
    const v = scan.vulnerabilities.find((x) => x.cve_id === ref);
    if (!v) return <div className="p-5 text-sm text-zinc-500">{ref} is not in this scan.</div>;
    return (
      <div className="p-5">
        <div className="flex items-center gap-2">
          <h3 className="font-mono text-base font-semibold text-zinc-100">{v.cve_id}</h3>
          <SeverityBadge severity={severityOf(v)} />
        </div>
        <div className="mt-3"><Row label="Risk score"><RiskBar value={v.risk_score} /></Row></div>
        <Row label="CVSS">{fmtNum(v.cvss_score)} {v.cvss_version ? <span className="text-zinc-500">v{v.cvss_version}</span> : null}</Row>
        <Row label="EPSS">{fmtPct(v.epss_score, 2)} {v.epss_percentile != null ? <span className="text-zinc-500">(p{Math.round(v.epss_percentile * 100)})</span> : null}</Row>
        <Row label="KEV probability">{fmtPct(v.kev_probability, 1)}</Row>
        <Row label="Published">{v.published ? v.published.slice(0, 10) : "—"}</Row>
        <Row label="Hosts"><List items={v.hosts.map((ip) => ["i:" + ip, ip])} onPick={onSelect} /></Row>
        <Row label="Confidence">Potential{v.backport_suspect ? " · possible back-port" : ""}</Row>
        <p className="mt-3 text-[13px] leading-relaxed text-zinc-400">{v.description || "No NVD description in the local cache."}</p>
        <a className="mt-3 inline-block text-xs text-amber-300 hover:underline" href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer">Open in NVD ↗</a>
      </div>
    );
  }

  if (kind === "i") {
    const h = scan.hosts.find((x) => x.ip === ref);
    if (!h) return null;
    const top = scan.vulnerabilities.filter((v) => v.hosts.includes(h.ip)).slice(0, 8);
    return (
      <div className="p-5">
        <h3 className="font-mono text-base font-semibold text-zinc-100">{h.ip}</h3>
        <p className="mt-0.5 text-xs text-zinc-500">{h.origin_hidden ? `Behind ${h.cdn}: origin hidden, not assessed` : h.internetdb ? "Shodan InternetDB record" : "Shodan has no data for this IP"}</p>
        <div className="mt-3">
          <Row label="Subdomains"><List items={h.subdomains.map((s) => [s === scan.domain ? `d:${s}` : `s:${s}`, s])} onPick={onSelect} /></Row>
          <Row label="Open ports"><List items={h.ports.map((p) => [null, `${p}${PORT_NAMES[p] ? "/" + PORT_NAMES[p] : ""}`])} /></Row>
          <Row label="Software"><List items={h.cpes.map((c) => [null, c.replace(/^cpe:\/[aho]:/, "")])} /></Row>
          {h.hostnames?.length ? <Row label="PTR / hostnames"><List items={h.hostnames.map((n) => [null, n])} /></Row> : null}
          {h.tags?.length ? <Row label="Tags"><List items={h.tags.map((t) => [null, t])} mono={false} /></Row> : null}
          <Row label="CVEs">{h.cves.length}</Row>
          <Row label="Max risk"><RiskBar value={h.max_risk} /></Row>
        </div>
        {top.length ? (
          <>
            <h4 className="mt-4 text-xs font-semibold uppercase tracking-wider text-zinc-500">Highest-risk CVEs</h4>
            <div className="mt-1">
              {top.map((v) => (
                <button key={v.cve_id} type="button" onClick={() => onSelect("c:" + v.cve_id)} className="flex w-full items-center justify-between gap-2 rounded px-1 py-1 text-left text-[13px] hover:bg-white/[0.04]">
                  <span className="font-mono text-zinc-200">{v.cve_id}</span>
                  <RiskBar value={v.risk_score} />
                </button>
              ))}
            </div>
          </>
        ) : null}
      </div>
    );
  }

  if (kind === "s" || kind === "d") {
    const sub = scan.subdomains.find((s) => s.name === ref);
    return (
      <div className="p-5">
        <h3 className="break-all font-mono text-base font-semibold text-zinc-100">{ref}</h3>
        <p className="mt-0.5 text-xs text-zinc-500">{kind === "d" ? "Root domain" : "Subdomain from Certificate Transparency"}</p>
        <div className="mt-3">
          <Row label="Resolves to"><List items={(sub?.ips || []).map((ip) => ["i:" + ip, ip])} onPick={onSelect} /></Row>
          {kind === "d" ? (
            <>
              <Row label="Subdomains">{scan.stats.subdomains}</Row>
              <Row label="Certificates seen">{scan.stats.certificates_seen ?? "—"}</Row>
              <Row label="Unresolved names">{scan.stats.unresolved}</Row>
            </>
          ) : null}
        </div>
      </div>
    );
  }

  if (kind === "svc") {
    const [ip, vendor, product] = rest;
    return (
      <div className="p-5">
        <h3 className="font-mono text-base font-semibold text-zinc-100">{product ? product.replace(/_/g, " ") : vendor === "other" ? "Unattributed software" : "Open ports"}</h3>
        <p className="mt-0.5 text-xs text-zinc-500">{vendor && vendor !== "other" && vendor !== "ports" ? `Vendor: ${vendor}` : "CVEs whose description names no CPE on this host"}</p>
        <div className="mt-3"><Row label="Host"><List items={[["i:" + ip, ip]]} onPick={onSelect} /></Row></div>
      </div>
    );
  }
  return null;
}
