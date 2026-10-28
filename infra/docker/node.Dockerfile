# Warden Node services: the MCP security gateway and the evaluation lab servers.
# One image carries both the `warden-gateway` and `warden-lab` (and `warden-policy`) binaries;
# compose/Helm pick the service with `command:`. Built from the pnpm workspace, then pruned
# to production dependencies so the runtime layer stays lean.
#
#   docker build -f infra/docker/node.Dockerfile -t warden/node:dev .

# ---- build: install everything and compile the TypeScript packages ----
# Base image is overridable (private mirror, or a base with a corporate proxy CA baked in).
ARG NODE_IMAGE=node:22-bookworm-slim
FROM ${NODE_IMAGE} AS build
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH
RUN corepack enable
WORKDIR /app

# Manifests first so dependency install caches across source-only changes.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY packages/policy-ir/package.json packages/policy-ir/
COPY packages/gateway/package.json packages/gateway/
COPY packages/lab-servers/package.json packages/lab-servers/
COPY apps/dashboard/package.json apps/dashboard/
RUN pnpm install --frozen-lockfile --filter "./packages/**..."

COPY packages ./packages
COPY policies ./policies
COPY data ./data
RUN pnpm -r --filter "./packages/**" run build

# ---- prune: a second, production-only dependency tree ----
FROM ${NODE_IMAGE} AS prune
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH
RUN corepack enable
WORKDIR /app
COPY --from=build /app /app
RUN pnpm install --frozen-lockfile --prod --filter "./packages/**..." \
    && pnpm store prune || true

# ---- runtime ----
FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
# Unprivileged user; a fixed uid keeps mounted-volume permissions predictable.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin warden \
    # Mount points for the shared policy volume and the verdict log: a fresh named volume inherits
    # this ownership, so the unprivileged user can write to it.
    && mkdir -p /policy /var/warden && chown warden:warden /policy /var/warden
WORKDIR /app
COPY --from=prune --chown=warden:warden /app /app
# The policy CLI, gateway and lab bins are on PATH via the workspace node_modules/.bin.
ENV PATH=/app/node_modules/.bin:$PATH
USER warden
EXPOSE 8787 8790
# Default to the gateway; compose/Helm override for the lab.
ENTRYPOINT ["node"]
CMD ["packages/gateway/dist/cli.js", "serve", "--config", "/etc/warden/warden.yaml"]
