# Warden dashboard

Next.js dashboard for Warden: live attack feed (SSE), tool inventory and pin status, pending
step-up approvals, and OWASP Top 10 coverage. It talks only to same-origin `/admin/*` (reverse-
proxied to the gateway admin API) and `/control/*` (the control plane); set `WARDEN_GATEWAY_URL`
and `WARDEN_CONTROL_URL` (see `next.config.ts`).

```bash
pnpm --filter @warden/dashboard dev     # http://localhost:3000
pnpm --filter @warden/dashboard build
pnpm --filter @warden/dashboard test:e2e  # Playwright against a built-in stub API
```
