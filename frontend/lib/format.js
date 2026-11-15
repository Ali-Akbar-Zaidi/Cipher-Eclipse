// Shared formatting + colour tokens for severities and entity kinds.

export const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };

// CVE node / badge colours. CRITICAL and HIGH are the deep reds the threat graph is built around.
export const SEVERITY_STYLE = {
  CRITICAL: { fill: "#5c0b0b", border: "#ef4444", text: "#fecaca", badge: "bg-red-950 text-red-200 ring-red-500/60" },
  HIGH: { fill: "#7f1d1d", border: "#f87171", text: "#fee2e2", badge: "bg-red-900/70 text-red-100 ring-red-400/50" },
  MEDIUM: { fill: "#4a3410", border: "#f59e0b", text: "#fde68a", badge: "bg-amber-950 text-amber-200 ring-amber-500/50" },
  LOW: { fill: "#132a3d", border: "#38bdf8", text: "#bae6fd", badge: "bg-sky-950 text-sky-200 ring-sky-500/50" },
  NONE: { fill: "#1f2330", border: "#6b7280", text: "#d1d5db", badge: "bg-zinc-800 text-zinc-300 ring-zinc-500/50" },
};

export const KIND_STYLE = {
  domain: { fill: "#2a1d05", border: "#f5a524", text: "#fde7b0", tag: "Domain" },
  subdomain: { fill: "#161c2e", border: "#6d83f2", text: "#d5dcff", tag: "Subdomain" },
  ip: { fill: "#0f2525", border: "#2dd4bf", text: "#ccfbf1", tag: "IP" },
  cdn: { fill: "#1b1d24", border: "#52525b", text: "#a1a1aa", tag: "Origin hidden" },
  service: { fill: "#1f1730", border: "#a78bfa", text: "#e9d5ff", tag: "Service" },
  more: { fill: "#15171e", border: "#3f3f46", text: "#a1a1aa", tag: "More" },
};

export function severityOf(v) {
  const s = (v?.severity || "").toUpperCase();
  if (s in SEVERITY_ORDER) return s;
  const c = v?.cvss_score;
  if (c == null) return "NONE";
  return c >= 9 ? "CRITICAL" : c >= 7 ? "HIGH" : c >= 4 ? "MEDIUM" : c > 0 ? "LOW" : "NONE";
}

export function riskTier(score) {
  if (score == null) return "NONE";
  return score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
}

export const fmtNum = (x, d = 1) => (x == null || Number.isNaN(x) ? "—" : Number(x).toFixed(d));
export const fmtPct = (x, d = 1) => (x == null ? "—" : `${(x * 100).toFixed(d)}%`);

// Well-known port names: InternetDB returns port numbers only (no banners).
export const PORT_NAMES = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 123: "ntp",
  143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
  1433: "mssql", 1521: "oracle", 2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgres",
  5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
  11211: "memcached", 27017: "mongodb",
};

export function parseCpe(cpe) {
  // cpe:/a:apache:http_server:2.4.7  or  cpe:2.3:a:apache:http_server:2.4.7:...
  const parts = cpe.replace(/^cpe:2\.3:/, "cpe:/").replace(/^cpe:\//, "").split(":");
  const [part, vendor = "", product = "", version = ""] = parts;
  const pretty = (s) => s.replace(/_/g, " ");
  return {
    part,
    vendor,
    product,
    version: version && version !== "*" && version !== "-" ? version : "",
    label: `${pretty(product || vendor)}${version && version !== "*" ? " " + version : ""}`.trim(),
    isOs: part === "o",
  };
}
