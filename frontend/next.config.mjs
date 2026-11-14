/** @type {import('next').NextConfig} */
const nextConfig = {
  // REQUIRED by frontend/Dockerfile: emit a self-contained server in .next/standalone.
  output: "standalone",
};

export default nextConfig;
