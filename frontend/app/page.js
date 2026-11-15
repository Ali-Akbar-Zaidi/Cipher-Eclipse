"use client";

import { useEffect, useRef, useState } from "react";
import DataTables from "@/components/DataTables";
import DetailsPanel from "@/components/DetailsPanel";
import SummaryPanel from "@/components/SummaryPanel";
import ThreatGraph from "@/components/ThreatGraph";
import { getHealth, startScan } from "@/lib/api";

const SAMPLE_TARGETS = ["nmap.org", "vulnweb.com"];
const STAGES = [
  [0, "Reading Certificate Transparency logs (crt.sh)"],
  [8, "Resolving subdomains through public DNS"],
  [18, "Filtering CDN edge addresses"],
  [22, "Looking up exposed services in Shodan InternetDB"],
  [28, "Scoring CVEs with CVSS, EPSS and the KEV model"],
  [34, "Writing and fact-checking the executive summary"],
];

function Stat({ label, value, tone = "text-zinc-100", hint }) {
  return (
    <div className="ce-panel px-4 py-3" title={hint}>
      <div className="text-[11px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${tone}`}>{value ?? "—"}</div>
    </div>
  );
}

function HealthPill({ health }) {
  if (health === undefined) return null;
  const ok = health && health.vulndb_ready;
  return (
    <span className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] ring-1 ${ok ? "text-emerald-300 ring-emerald-500/30" : health ? "text-amber-300 ring-amber-500/30" : "text-red-300 ring-red-500/30"}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-400" : health ? "bg-amber-400" : "bg-red-400"}`} />
      {ok ? `API ready${health.llm_configured ? " · LLM on" : " · LLM off"}` : health ? "Vulnerability DB building" : "API offline"}
    </span>
  );
}

export default function Home() {
  const [domain, setDomain] = useState("");
  const [useLlm, setUseLlm] = useState(true);
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [selectedId, setSelectedId] = useState(null);
  const [health, setHealth] = useState(undefined);
  const abortRef = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => {
    getHealth().then(setHealth);
  }, []);

  useEffect(() => {
    if (!loading) return;
    const t0 = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 500);
    return () => clearInterval(id);
  }, [loading]);

  async function run(target) {
    const d = (target ?? domain).trim();
    if (!d) return;
    setDomain(d);
    setError(null);
    setLoading(true);
    setElapsed(0);
    setSelectedId(null);
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const result = await startScan(d, { useLlm, signal: ctrl.signal });
      setScan(result);
    } catch (err) {
      if (err.name !== "AbortError") setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cipher-eclipse-${scan.domain}-${scan.started_at?.slice(0, 10) || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function importJson(e) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    try {
      const data = JSON.parse(await file.text());
      if (!data?.domain || !Array.isArray(data.vulnerabilities) || !Array.isArray(data.hosts)) throw new Error("Not a Cipher Eclipse scan file.");
      setScan(data);
      setDomain(data.domain);
      setSelectedId(null);
      setError(null);
    } catch (err) {
      setError(`Could not open file: ${err.message}`);
    }
  }

  const stage = [...STAGES].reverse().find(([t]) => elapsed >= t)?.[1];
  const st = scan?.stats;

  return (
    <div className="mx-auto max-w-[1500px] px-4 pb-16 sm:px-6">
      <header className="flex flex-wrap items-center gap-3 py-5">
        <div className="flex items-center gap-2.5">
          <span aria-hidden className="relative inline-block h-7 w-7 rounded-full bg-[#0b0d12] shadow-[0_0_0_2px_#f5a524,0_0_18px_4px_rgba(245,165,36,0.45)]" />
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-zinc-100">Cipher Eclipse</h1>
            <p className="text-[11px] text-zinc-500">Passive attack-surface mapping · exploit-aware prioritisation</p>
          </div>
        </div>
        <div className="ml-auto"><HealthPill health={health} /></div>
      </header>

      <form
        className="ce-panel flex flex-wrap items-center gap-3 p-3"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <label htmlFor="domain" className="sr-only">Target domain</label>
        <input
          id="domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Target domain, e.g. nmap.org"
          className="ce-input min-w-0 flex-1 basis-64 py-2 font-mono text-[15px]"
          autoComplete="off"
          spellCheck={false}
          disabled={loading}
        />
        <label className="flex items-center gap-2 text-xs text-zinc-400">
          <input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} className="accent-amber-400" disabled={loading} />
          LLM summary
        </label>
        {loading ? (
          <button type="button" className="ce-btn-secondary" onClick={() => abortRef.current?.abort()}>Cancel</button>
        ) : (
          <button type="submit" className="ce-btn" disabled={!domain.trim()}>Scan</button>
        )}
        <div className="flex gap-2">
          <button type="button" className="ce-btn-secondary" onClick={() => fileRef.current?.click()} disabled={loading}>Open JSON</button>
          {scan && <button type="button" className="ce-btn-secondary" onClick={exportJson} disabled={loading}>Export JSON</button>}
          <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={importJson} />
        </div>
      </form>
      <p className="mt-2 px-1 text-[11px] text-zinc-500">
        Passive only: data comes from crt.sh, public DNS, Shodan InternetDB, NVD, EPSS and CISA KEV. No traffic is sent to the target.
        Scan only domains you own, public test sites, or programmes that permit research.
      </p>

      {error && (
        <div role="alert" className="mt-4 rounded-md border border-red-500/40 bg-red-950/40 px-4 py-3 text-sm text-red-200">{error}</div>
      )}

      {loading && (
        <div className="ce-panel mt-6 flex flex-col items-center gap-3 px-6 py-14 text-center">
          <div className="ce-eclipse" aria-hidden />
          <p className="text-sm text-zinc-200">Scanning <span className="font-mono">{domain}</span> · {elapsed}s</p>
          <p className="text-xs text-zinc-500">{stage}… (usually 30–90 s, mostly waiting on crt.sh)</p>
        </div>
      )}

      {!loading && !scan && !error && (
        <div className="ce-panel mt-6 px-6 py-14 text-center">
          <p className="text-base text-zinc-200">Map what an organisation exposes to the internet, then see what to fix first.</p>
          <p className="mx-auto mt-2 max-w-xl text-sm text-zinc-500">
            Root domain → subdomains → IPs → services → CVEs, ranked by a model trained to predict which CVEs end up in CISA&apos;s Known Exploited Vulnerabilities catalogue.
          </p>
          <div className="mt-5 flex justify-center gap-2">
            {SAMPLE_TARGETS.map((t) => (
              <button key={t} type="button" onClick={() => run(t)} className="rounded-full bg-white/[0.05] px-3 py-1 font-mono text-xs text-zinc-300 ring-1 ring-[var(--line)] hover:text-amber-200">
                {t}
              </button>
            ))}
          </div>
          <p className="mt-2 text-[11px] text-zinc-600">Public test targets</p>
        </div>
      )}

      {scan && !loading && (
        <main className="mt-6 space-y-5">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <Stat label="Subdomains" value={st.subdomains} />
            <Stat label="IP addresses" value={st.unique_ips} />
            <Stat label="Origin hidden" value={st.origin_hidden} tone="text-zinc-400" hint="Behind a CDN: not looked up" />
            <Stat label="Potential CVEs" value={st.vulnerabilities} />
            <Stat label="Critical / High" value={`${st.critical} / ${st.high}`} tone="text-red-400" />
            <Stat label="KEV-likely" value={st.kev_likely} tone="text-amber-300" hint="CVEs the model gives a ≥10% chance of being in CISA KEV" />
          </div>
          {scan.warnings?.length ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-950/30 px-4 py-2 text-xs text-amber-200">{scan.warnings.join(" ")}</div>
          ) : null}

          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
            <section className="ce-panel h-[640px] overflow-hidden">
              <ThreatGraph scan={scan} selectedId={selectedId} onSelect={setSelectedId} />
            </section>
            <aside className="ce-panel max-h-[640px] overflow-auto">
              <DetailsPanel scan={scan} selectedId={selectedId} onSelect={setSelectedId} />
            </aside>
          </div>

          <SummaryPanel summary={scan.summary} onSelect={setSelectedId} />
          <DataTables scan={scan} onSelect={setSelectedId} selectedId={selectedId} />

          <p className="text-[11px] text-zinc-600">
            Scan {scan.scan_id} · {scan.started_at} · {scan.timings?.total}s total
            {scan.pipeline ? ` · pipeline: ${Object.entries(scan.pipeline).map(([k, v]) => `${k}=${v}`).join(", ")}` : ""}
          </p>
        </main>
      )}
    </div>
  );
}
