// Turns a /api/scan payload into React Flow nodes + edges with a dagre layout.
//
// Hierarchy:  Root domain -> Subdomains -> Resolved IPs -> Services (CPEs) -> CVEs
//
// InternetDB reports CVEs per host, not per software package, so each CVE is
// attached to the CPE whose product name appears in the NVD description
// (e.g. "Apache HTTP Server" -> cpe:/a:apache:http_server). CVEs that match no
// CPE hang off an "unattributed" service node on that host, so the hierarchy
// stays intact without inventing a link the data does not support.

import dagre from "@dagrejs/dagre";
import { parseCpe, severityOf } from "./format";

export const NODE_W = 210;
export const NODE_H = 52;

// Extra names NVD descriptions use for common products.
const PRODUCT_ALIASES = {
  http_server: ["httpd", "mod_", "apache 2."],
  nginx: ["nginx"],
  internet_information_services: ["iis"],
  openssh: ["openssh", "sshd"],
};

function productMatches(cpe, description, vendorUnique) {
  if (!description || !cpe.product) return false;
  const d = description.toLowerCase();
  const product = cpe.product.toLowerCase();
  if (d.includes(product.replace(/_/g, " ")) || d.includes(product)) return true;
  if ((PRODUCT_ALIASES[product] || []).some((a) => d.includes(a))) return true;
  // Only one product from this vendor on the host: the vendor name is enough.
  return vendorUnique && cpe.vendor.length > 2 && d.includes(cpe.vendor.toLowerCase());
}

export function buildGraph(scan, { cvesPerService = 8, minRisk = 0 } = {}) {
  const nodes = [];
  const edges = [];
  const seen = new Set();
  const vulnById = new Map((scan.vulnerabilities || []).map((v) => [v.cve_id, v]));

  const addNode = (id, kind, data) => {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, type: "entity", position: { x: 0, y: 0 }, data: { kind, ...data } });
  };
  const addEdge = (source, target, extra = {}) => {
    const id = `${source}->${target}`;
    if (seen.has(id)) return;
    seen.add(id);
    edges.push({ id, source, target, type: "smoothstep", ...extra });
  };

  const rootId = `d:${scan.domain}`;
  addNode(rootId, "domain", { label: scan.domain, sub: `${scan.stats?.subdomains ?? 0} subdomains`, ref: scan.domain });

  const hostByIp = new Map((scan.hosts || []).map((h) => [h.ip, h]));

  for (const sub of scan.subdomains || []) {
    const sid = `s:${sub.name}`;
    if (sub.name !== scan.domain) {
      addNode(sid, "subdomain", { label: sub.name, sub: `${sub.ips.length} IP${sub.ips.length === 1 ? "" : "s"}`, ref: sub.name });
      addEdge(rootId, sid);
    }
    const parent = sub.name === scan.domain ? rootId : sid;

    for (const ip of sub.ips) {
      const host = hostByIp.get(ip) || { ip };
      const iid = `i:${ip}`;
      const kind = host.origin_hidden ? "cdn" : "ip";
      const sub_ = host.origin_hidden
        ? `Origin hidden · ${host.cdn || "CDN"}`
        : host.internetdb
          ? `${host.ports?.length || 0} ports · ${host.cves?.length || 0} CVEs`
          : "No InternetDB data";
      addNode(iid, kind, { label: ip, sub: sub_, ref: ip, risk: host.max_risk });
      addEdge(parent, iid);
    }
  }

  // Services + CVEs per scanned host
  for (const host of scan.hosts || []) {
    if (host.origin_hidden || !host.internetdb) continue;
    const iid = `i:${host.ip}`;
    const cpes = (host.cpes || []).map(parseCpe).filter((c) => !c.isOs);
    const buckets = new Map(cpes.map((c) => [c, []]));
    const unattributed = [];
    const vendorCount = cpes.reduce((m, c) => m.set(c.vendor, (m.get(c.vendor) || 0) + 1), new Map());

    for (const cveId of host.cves || []) {
      const v = vulnById.get(cveId) || { cve_id: cveId };
      if ((v.risk_score ?? 0) < minRisk) continue;
      const match =
        cpes.find((c) => productMatches(c, v.description, false)) ||
        cpes.find((c) => productMatches(c, v.description, vendorCount.get(c.vendor) === 1));
      (match ? buckets.get(match) : unattributed).push(v);
    }

    const services = [...buckets.entries()].map(([cpe, list]) => ({ id: `svc:${host.ip}:${cpe.vendor}:${cpe.product}`, label: cpe.label, sub: cpe.vendor, list, cpe }));
    if (unattributed.length) {
      services.push({ id: `svc:${host.ip}:other`, label: "Unattributed software", sub: "CVE not matched to a CPE", list: unattributed });
    }
    if (!services.length && host.ports?.length) {
      services.push({ id: `svc:${host.ip}:ports`, label: `Ports ${host.ports.join(", ")}`, sub: "no CPEs reported", list: [] });
    }

    for (const svc of services) {
      addNode(svc.id, "service", { label: svc.label, sub: `${svc.sub} · ${svc.list.length} CVE${svc.list.length === 1 ? "" : "s"}`, ref: host.ip, cpe: svc.cpe });
      addEdge(iid, svc.id);
      const sorted = [...svc.list].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
      const shown = cvesPerService === Infinity ? sorted : sorted.slice(0, cvesPerService);
      for (const v of shown) {
        const cid = `c:${v.cve_id}`;
        const sev = severityOf(v);
        addNode(cid, "cve", {
          label: v.cve_id,
          sub: `risk ${v.risk_score != null ? Math.round(v.risk_score) : "—"} · CVSS ${v.cvss_score ?? "—"}`,
          severity: sev,
          risk: v.risk_score,
          kevLikely: (v.kev_probability ?? 0) >= 0.1,
          ref: v.cve_id,
        });
        addEdge(svc.id, cid, sev === "CRITICAL" || sev === "HIGH" ? { data: { hot: true } } : {});
      }
      const hidden = sorted.length - shown.length;
      if (hidden > 0) {
        const mid = `more:${svc.id}`;
        addNode(mid, "more", { label: `+${hidden} more CVEs`, sub: "see the table below", ref: host.ip });
        addEdge(svc.id, mid);
      }
    }
  }

  return layout(nodes, edges);
}

function layout(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 14, ranksep: 70, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return {
    nodes: nodes.map((n) => {
      const p = g.node(n.id);
      return { ...n, position: { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 } };
    }),
    edges,
  };
}
