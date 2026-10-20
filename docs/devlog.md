# Devlog

Short log of this repository's sessions, newest first. The project-wide devlog (all sessions) is
in [tapestry-playground](https://github.com/nascencestudio/tapestry-playground/blob/main/docs/devlog.md).

---

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
