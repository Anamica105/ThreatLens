import type { NextConfig } from "next";

const API_URL = process.env.THREATLENS_API_URL || "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  distDir: process.env.NEXT_DIST_DIR || ".next",
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_URL}/api/:path*` }];
  },
  async redirects() {
    return [{ source: "/", destination: "/dashboard", permanent: false }];
  },
  // Long-running exports (PDF) go through the rewrite proxy.
  experimental: { proxyTimeout: 180_000 },
};

export default nextConfig;
