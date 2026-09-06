# syntax=docker/dockerfile:1.7

# Certificate Inspector
#
# The app is a static export, so the runtime image is nginx with a directory of
# files — no Node, no application server, nothing that could receive a
# certificate. That is the same guarantee the UI makes, enforced by what is
# absent from the image.

ARG NODE_VERSION=22-alpine
ARG NGINX_VERSION=1.29-alpine

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
# Pinned to the build platform on purpose: the output of the build is static
# HTML/JS, identical on every architecture, so there is no reason to run npm
# under QEMU emulation when building the arm64 image.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION} AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION} AS builder

WORKDIR /app
# NODE_ENV is deliberately left alone: `next build` sets production mode itself,
# and forcing it here only risks confusing tooling that reads it during the build.
ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Produces ./out — see `output: 'export'` in next.config.ts.
RUN npm run build

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
# nginx-unprivileged runs as UID 101 and listens on 8080, so the container needs
# no root and no capabilities.
FROM nginxinc/nginx-unprivileged:${NGINX_VERSION} AS runner

# The Alpine packages inside the base image are as old as its last rebuild, which
# is not our schedule to keep: at the time of writing 1.29-alpine shipped 33
# fixable HIGH advisories in curl, openssl, util-linux, expat, libxml2 and c-ares,
# every one of them already patched in the v3.23 branch the image points at. So
# take the patches at build time instead of waiting for the maintainer, and let
# the weekly rebuild in CI be the thing that keeps them current.
#
# The cost is honest: the contents of this layer depend on when it was built, so
# two builds of one commit are no longer byte-identical. The smoke test in CI runs
# against exactly what gets published, which is what catches an upgrade that
# breaks something.
USER root
RUN apk upgrade --no-cache
# Root is dropped again by the USER 101 at the end of this stage, which the smoke
# test verifies by reading the running container's uid.

# CI adds source, revision and created labels via docker/metadata-action.
LABEL org.opencontainers.image.title="Certificate Inspector" \
      org.opencontainers.image.description="X.509 certificate and chain inspector that parses everything in the browser"

COPY docker/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY docker/default.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/out /usr/share/nginx/html

EXPOSE 8080

# busybox wget ships with the alpine base; no extra package needed.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

USER 101
