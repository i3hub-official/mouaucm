import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  compress: true,
  productionBrowserSourceMaps: false,

  turbopack: {},

  experimental: {
    serverActions: {
      bodySizeLimit: "10mb",
    },
  },

  // ENFORCE HTTPS + Security Headers
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-DNS-Prefetch-Control", value: "on" },

          // Force HTTPS (HSTS)
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },

          // Force redirect to HTTPS in production
          {
            key: "Content-Security-Policy",
            value: "upgrade-insecure-requests", // Auto-upgrade HTTP → HTTPS
          },

          { key: "X-XSS-Protection", value: "1; mode=block" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },

          // Secure cookies + prevent fingerprinting
          {
            key: "Permissions-Policy",
            value:
              "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
        ],
      },
    ];
  },

  images: {
    remotePatterns: [
      { protocol: "https", hostname: "res.cloudinary.com", pathname: "/**" },
      { protocol: "https", hostname: "ui-avatars.com", pathname: "/**" },
      { protocol: "https", hostname: "i.pravatar.cc", pathname: "/**" },
      { protocol: "https", hostname: "images.unsplash.com", pathname: "/**" },
      { protocol: "https", hostname: "**.pexels.com", pathname: "/**" },
      { protocol: "https", hostname: "geeksforgeeks.org", pathname: "/**" },
    ],
    minimumCacheTTL: 60,
  },

  output: process.env.DOCKER_BUILD ? "standalone" : undefined,

  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },

 // COOKIE_SECURE=true
};

export default nextConfig;