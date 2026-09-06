import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  /**
   * The app has no server side: every certificate is parsed in the browser and
   * nothing is ever sent anywhere. Exporting to plain HTML/JS makes that
   * structural rather than a promise — the container that serves the app has no
   * application runtime that could receive a certificate in the first place.
   *
   * Security headers cannot be set from here in an export; they live in
   * `docker/nginx.conf` instead.
   */
  output: 'export',

  // Emit `route/index.html`, so any static file server resolves routes without
  // needing rewrite rules.
  trailingSlash: true,
};

export default nextConfig;
