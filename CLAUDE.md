# CLAUDE.md: @nascencestudio/ipguard

The source of truth for anyone (human or AI) working in this repo. Read it at the start of every
session and keep it current.

## What it is

IP protection for StudioCMS sites ([ADR 0001](docs/decisions/0001-ipguard.md)): whitelist / flagged /
blacklist / banned lists (addresses or CIDR ranges), rate limiting, AbuseIPDB reputation checks, site-wide
bans (middleware), Dashboard → Admin → IP Guard, and `@nascencestudio/ipguard/guard` for other plugins
(webforms). Designed after the user's Drupal module `nh_form_submission_blocker`. No dependency on
Tapestry. Nascence Studio, MIT.

Sibling checkouts in `/Volumes/T7/www/`: `tapestry/`, `medialibrary/`, `tapestry-seo/`, `tapestry-menus/`,
`webforms/`, `tapestry-playground/` (dev site and browser tests: `e2e/ipguard.e2e.mjs`, IP Guard states in
`e2e/a11y.e2e.mjs`, the dev-only `src/pages/e2e/ipguard-check.ts`), and this repo. The devlog of record for
the whole project is the playground's; this repo has its own short one.

## Status

- **0.1.0 released 2026-10-31** (GitHub `nascencestudio/ipguard`, npm with provenance). Releases: bump
  `version`, PR, merge, GitHub release `v<version>`, approve the staged version on npmjs.com (trusted
  publishing only; no tokens).

## Rules

1. **Security first.** pnpm only (never npm/npx/yarn; `pnpm view`). Hardening in `pnpm-workspace.yaml`
   with written reasons. Pin exact versions. No runtime dependencies (keep it that way, or write an ADR).
   `pnpm audit` must pass. No Meta libraries.
2. **This code decides who gets blocked.** Fail open on our own failures (AbuseIPDB, storage, unknown
   address); never act on whitelisted addresses; every way of blocking goes through `refusalFor()`.
3. **Document everything:** devlog entry each session; decisions as ADRs (`docs/decisions`, 0001+).
4. **Tests with every change**, adversarial for parsing and the decision table. UI changes: keep the
   playground's `ipguard` and `a11y` suites passing.

## Layout

```
src/
├── index.ts          ← plugin: options (trustedProxies, abuseIpDbEndpoint), route, middleware, virtual:ipguard/config, dashboard page
├── ip.ts             ← parse/format IPv4+IPv6, CIDR, subjectOf (/64), isPublic, resolveClientIp (pure)
├── model.ts          ← Entry, Settings, parse*, listsOf, decide (the table), refusalFor (lockout guard) (pure)
├── abuseipdb.ts      ← the client: header key, timeout, cache, fail open, 401/429 pause (fetch + store injected)
├── admin.ts          ← dashboard forms as data: parseAdd, selectedIds, parseSettingsForm, ERRORS (pure)
├── virtual.d.ts      ← virtual:ipguard/config
└── runtime/          ← store.ts (plugin data rows, 10 s cache, lazy cleanup), guard.ts (`/guard`: checkAction,
                         recordAttempt, clientIp), middleware.ts (bans), admin-endpoint.ts (/_ipguard/admin),
                         IpGuardNav.astro + IpGuardPage.astro (dashboard), viewer.ts
```

## Commands

| Command | |
| --- | --- |
| `pnpm install` / `pnpm build` / `pnpm test` / `pnpm typecheck` / `pnpm lint` / `pnpm audit` | |
| Release | Bump `version`, PR, merge, GitHub release `v<version>`, approve the staged version on npm. Never publish locally. |

## Gotchas

- StudioCMS names the page `/dashboard/nascencestudio_ipguard/ipguard`; admin-only pages appear in the
  **Admin** section of the sidebar.
- Astro refuses cross-site form POSTs before our code runs ("Cross-site POST form submissions are
  forbidden"): tests must send `Origin`.
- In dev the browser connects from `::1` or `127.0.0.1` (trusted proxies), so tests set the visitor with
  `X-Forwarded-For`. In production behind Caddy the same header carries the real address.
- `203.0.113.0/24`, `198.51.100.0/24` and `2001:db8::/32` are documentation ranges: never "public", so
  AbuseIPDB is never asked about them (good for tests; use them).
- Entries and settings are cached in memory for 10 s per server process; writes drop the cache. Changes
  made directly in the database show up within 10 s.
- Row buttons in the dashboard belong to a hidden per-row form (`form="ig-row-<id>"`): forms can't nest
  inside the bulk-selection form.
