import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { NextConfig } from 'next';

/**
 * The version shown in the footer comes from package.json, so `npm version`
 * remains the single place a release is declared. Reading it here inlines the
 * string at build time; importing package.json from a component instead would
 * ship the whole dependency list to the browser, and the point of a static
 * export is that the bundle reveals no inventory to scan.
 */
const { version } = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'package.json'), 'utf8'),
) as { version: string };

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

  env: {
    NEXT_PUBLIC_APP_VERSION: version,
  },
};

export default nextConfig;
