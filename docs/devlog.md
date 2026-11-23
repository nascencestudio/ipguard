# Devlog

Short log of this repository's sessions, newest first. The project-wide devlog (all sessions) is
in [tapestry-playground](https://github.com/nascencestudio/tapestry-playground/blob/main/docs/devlog.md).

---

## 2026-11-23: Dev dependency refresh (no release)

- `astro` 7.4.1 → 7.4.13 (dev; clears GHSA-mh32-jxcr-mh9f, low, and GHSA-r3h5-4585-7x3w, moderate),
  `@biomejs/biome` 2.6.8, `vitest` 5.1.1, `@types/node` 22.20.5. No runtime dependencies changed, so no
  new version.
- `.nvmrc` 22.23.3 → 22.23.4: astro ≥ 7.4.7 requires node ≥ 22.23.4 (why Dependabot PR #6 failed CI).
- Biome 2.6 formats Markdown and YAML by default; both formatters are off in `biome.json`.
- Dependabot ignores `@types/node` majors (types follow `engines.node` ≥ 22). TypeScript 7 held.
- Verified: lint, typecheck, 32 unit tests, build, audit. Supersedes #6, closes #4.

## 2026-10-20: First version (0.1.0)

**Request:** IP protection for webforms, after the user's Drupal module (read in full; its behaviour
settled with the user: flagged addresses are blocked until reviewed, a high AbuseIPDB score blacklists,
a ban needs both signals, the whitelist protects, no self-bans). [ADR 0001](decisions/0001-ipguard.md).

### Done
- Pure core with 32 unit tests: address parsing (strict IPv4, IPv6 with RFC 5952 output, CIDR, /64
  subjects, public ranges, rightmost-untrusted `X-Forwarded-For`), the decision table, the lockout guard,
  the AbuseIPDB client (fakes for the network and cache), the dashboard's form parsing.
- Runtime: plugin data storage, `checkAction` / `recordAttempt`, ban middleware, admin endpoint, dashboard
  (Flagged, Blacklist, Banned, Whitelist, Settings, Check an address). No runtime dependencies.
- Playground: `ipguard` suite (9 steps) and every view in the a11y audit (both themes).
- Trusted proxies' own addresses are never judged: in dev (loopback) and behind a proxy that sent no
  `X-Forwarded-For`, every request had been counted as one visitor (found with webforms).

### Next
- Webforms (uses `checkAction`), then GitHub and the first release.
