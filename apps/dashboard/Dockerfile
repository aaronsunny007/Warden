# Warden operator dashboard (Next.js 16, standalone output).
# Build from the repo root so the pnpm workspace resolves:
#   docker build -f apps/dashboard/Dockerfile -t warden/dashboard:dev .

FROM node:25-bookworm-slim AS build
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH
RUN corepack enable
WORKDIR /app
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/dashboard/package.json apps/dashboard/
RUN pnpm install --frozen-lockfile --filter "@warden/dashboard..."
COPY apps/dashboard apps/dashboard
# WARDEN_STANDALONE switches next.config to output:standalone (a self-contained server bundle).
# Next compiles the rewrite destinations into the build, so the upstream URLs are fixed here;
# they use the short service names `gateway`/`control`, which resolve under both docker-compose
# and the Helm chart (same release namespace). Override via build args to retarget.
ARG WARDEN_GATEWAY_URL=http://gateway:8787
ARG WARDEN_CONTROL_URL=http://control:8008
ENV WARDEN_STANDALONE=1 NEXT_TELEMETRY_DISABLED=1 \
    WARDEN_GATEWAY_URL=$WARDEN_GATEWAY_URL WARDEN_CONTROL_URL=$WARDEN_CONTROL_URL
RUN pnpm --filter @warden/dashboard run build

FROM node:25-bookworm-slim AS runtime
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin warden
WORKDIR /app
# The standalone server and its trimmed node_modules, plus static assets.
COPY --from=build --chown=warden:warden /app/apps/dashboard/.next/standalone ./
COPY --from=build --chown=warden:warden /app/apps/dashboard/.next/static ./apps/dashboard/.next/static
COPY --from=build --chown=warden:warden /app/apps/dashboard/public ./apps/dashboard/public
USER warden
EXPOSE 3000
CMD ["node", "apps/dashboard/server.js"]
