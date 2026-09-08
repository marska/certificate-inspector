/**
 * The released version, inlined from package.json by `next.config.ts`.
 *
 * The fallback only shows up if something renders outside a Next build — the
 * unit tests, for instance — where no value has been substituted.
 */
export const APP_VERSION = process.env.NEXT_PUBLIC_APP_VERSION ?? 'dev';
