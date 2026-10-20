/**
 * next.config.js
 *
 * DEMO FIXTURE: deliberately insecure - source maps are published to
 * production, which lets anybody rebuild the original source code.
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  productionBrowserSourceMaps: true,
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
};

export default nextConfig;
