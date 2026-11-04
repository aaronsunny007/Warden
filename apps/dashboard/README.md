# Warden dashboard

Next.js dashboard for Warden: live attack feed (SSE), tool inventory and pin status, pending
step-up approvals, and OWASP Top 10 coverage. It talks only to same-origin `/admin/*` (reverse-
proxied to the gateway admin API) and `/control/*` (the control plane); set `WARDEN_GATEWAY_URL`
and `WARDEN_CONTROL_URL` (see `next.config.ts`). If `WARDEN_ADMIN_TOKEN` is set, `proxy.ts` adds it as a
bearer token to those calls on the server (the browser never sees it), so anyone who can open the dashboard
acts as an operator: keep it on a private network or behind your own login.

```bash
pnpm --filter @warden/dashboard dev     # http://localhost:3000
pnpm --filter @warden/dashboard build
pnpm --filter @warden/dashboard test:e2e  # Playwright against a built-in stub API
```
