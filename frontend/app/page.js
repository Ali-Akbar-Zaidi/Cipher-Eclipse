// PLACEHOLDER page: proves the frontend container can reach the backend.
// API_URL_INTERNAL is set by docker-compose (http://backend:8000); outside
// Docker it falls back to the public URL.
export const dynamic = "force-dynamic";

async function getHealth() {
  const base = process.env.API_URL_INTERNAL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  try {
    const res = await fetch(`${base}/health`, { cache: "no-store" });
    return await res.json();
  } catch (err) {
    return { status: "unreachable", error: String(err) };
  }
}

export default async function Home() {
  const health = await getHealth();
  return (
    <main>
      <h1>Cipher Eclipse</h1>
      <p>Frontend container is running. Backend health:</p>
      <pre>{JSON.stringify(health, null, 2)}</pre>
    </main>
  );
}
