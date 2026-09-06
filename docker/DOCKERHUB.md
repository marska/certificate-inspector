# Certificate Inspector

Paste a certificate, a Base64 blob, a DER file or a whole chain. The format is
detected automatically and every property is laid out in readable form: subject
and issuer, validity, SANs, key usage, basic constraints, fingerprints, the full
extension list, chain building with diagnostics, and raw OpenSSL / ASN.1 views.

**Nothing leaves the browser.** Certificates are parsed with WebCrypto and pkijs
on the client. Nothing is uploaded, logged, stored, sent to analytics or placed
in the URL.

That is structural, not a promise. The app is a static export, so this image
contains no application runtime at all — nginx serving a directory of files.
There is no endpoint that could receive a certificate, and the shipped
Content-Security-Policy sets `connect-src 'none'`, which makes the browser
refuse any outbound `fetch`, XHR, WebSocket or beacon from the page.

## Quick start

```bash
docker run --rm -p 8080:8080 marskadh/certificate-inspector
```

Then open <http://localhost:8080>.

## Tags

| Tag | Meaning |
| --- | --- |
| `latest` | Newest release. Follows releases only, never the branch tip. |
| `1`, `1.0` | Newest release within that major / minor. Moves. |
| `1.0.0` | One exact release. Does not move. |
| `edge` | Tip of `master`. Unreleased. |
| `sha-<short>` | One exact commit. |

Pin production deployments to a digest — `@sha256:...` — since tags can be
overwritten and digests cannot.

## The image

- Base `nginxinc/nginx-unprivileged:1.29-alpine`, running as UID 101, never root
- Listens on **8080**, not 80, because it does not run as root
- Healthcheck on `/healthz`
- `linux/amd64` and `linux/arm64`
- Security headers on every response: the CSP above, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, cross-origin
  isolation, and a `Permissions-Policy` denying camera, microphone, geolocation
  and the rest

Every published image is built only after typecheck, lint and the test suite
pass, and after the container itself is started and exercised: the page is
served, the JS bundle loads, the security headers are present, an unknown path
returns 404, and the process is not root.

## Source

[github.com/marska/certificate-inspector](https://github.com/marska/certificate-inspector) — GPL-3.0
