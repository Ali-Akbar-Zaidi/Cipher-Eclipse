export const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

async function parse(res) {
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON error page */
  }
  if (!res.ok) {
    const detail = typeof body?.detail === "string" ? body.detail : Array.isArray(body?.detail) ? body.detail.map((d) => d.msg).join("; ") : null;
    throw new Error(detail || `Request failed (HTTP ${res.status})`);
  }
  return body;
}

export async function startScan(domain, { useLlm = true, signal } = {}) {
  let res;
  try {
    res = await fetch(`${API_URL}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, use_llm: useLlm, include_summary: true }),
      signal,
    });
  } catch (err) {
    if (err.name === "AbortError") throw err;
    throw new Error(`Cannot reach the Cipher Eclipse API at ${API_URL}. Is the backend running?`);
  }
  return parse(res);
}

export async function getHealth() {
  try {
    return await parse(await fetch(`${API_URL}/health`, { cache: "no-store" }));
  } catch {
    return null;
  }
}
