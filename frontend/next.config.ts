import path from "path";
import type { NextConfig } from "next";

const HUNTER_API_BASE = (
  process.env.HUNTER_API_BASE || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const nextConfig: NextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: path.resolve(__dirname),
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${HUNTER_API_BASE}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
