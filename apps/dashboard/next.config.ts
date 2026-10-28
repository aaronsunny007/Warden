import type { NextConfig } from 'next';

/** The dashboard talks to the gateway admin API and the control plane. Both are reverse-proxied
 * here so the browser only ever calls same-origin /admin and /control paths. */
const config: NextConfig = {
  ...(process.env.WARDEN_STANDALONE ? { output: 'standalone' as const } : {}),
  async rewrites() {
    const gateway = process.env.WARDEN_GATEWAY_URL ?? 'http://127.0.0.1:8787';
    const control = process.env.WARDEN_CONTROL_URL ?? 'http://127.0.0.1:8008';
    return [
      { source: '/admin/:path*', destination: `${gateway}/api/v1/:path*` },
      { source: '/control/:path*', destination: `${control}/v1/:path*` },
    ];
  },
};

export default config;
