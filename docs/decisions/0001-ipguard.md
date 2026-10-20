# 0001. IP Guard: IP reputation, review lists and site-wide bans for StudioCMS

- Status: Accepted (2026-10-19).
- Date: 2026-10-19

## Context

Spam protection for `@nascencestudio/webforms` (its ADR 0001) needs to know about the **address** a
submission comes from, not only how the submission behaves. The user built this for Drupal as
`nh_form_submission_blocker`: submissions are checked against a whitelist and a blacklist, a rate limit
and AbuseIPDB (an abuse-report database with a 0–100 confidence score); suspicious addresses go to a
Flagged list for an admin to ban, blacklist, whitelist or dismiss; banned addresses can't load the site
at all. Its source was reviewed in full (2026-10-19) and is the specification for this plugin; it's
rebuilt in TypeScript, not ported. StudioCMS has nothing comparable.

## Decision

1. **A separate StudioCMS plugin**, `@nascencestudio/ipguard` (working name) *(user)*. It owns the lists,
   AbuseIPDB, rate limiting and site-wide bans; webforms uses it when it's installed (and works without
   it). Later it can protect the StudioCMS login page the same way. No dependency on Tapestry.
2. **Four lists**, each entry with a reason, who added it (or "automatic") and when:
   - **Whitelist**: never checked, never blocked or banned automatically *(user)*.
   - **Flagged**: waiting for review; the address **is blocked** from submitting until an admin acts
     *(user: "flag and block until reviewed")*. Actions: Ban, Blacklist, Whitelist, Dismiss (dismiss lets
     it submit again), one by one or in bulk.
   - **Blacklist**: submissions refused; optional expiry date; source (manual, AbuseIPDB, rate limit)
     and the AbuseIPDB score when it applies.
   - **Banned**: every request answered with a bare 403 before anything else runs (middleware).
   Entries can be single addresses or **ranges (CIDR)**. IPv6 addresses are matched by their /64 for
   automatic actions (one IPv6 visitor can rotate through a whole /64).
3. **The check, for each protected action (a form submission)**, in this order:
   1. Off, or whitelisted → allow.
   2. Banned, actively blacklisted or flagged → refuse.
   3. Rate limit (submissions per address per window; default 5 per hour) and AbuseIPDB score:
      - score ≥ threshold (default 75) **and** over the rate limit → **ban** (and blacklist);
      - score ≥ threshold → **blacklist** (forms only; the site stays reachable) *(user)*;
      - over the rate limit → **flag** (blocked until reviewed);
      - otherwise → allow, and count the submission.
   Webforms' own cheap checks (honeypot, timing, proof of work) run **before** this, so bots never cost an
   AbuseIPDB lookup; submissions they reject still count towards the rate limit (the Drupal module
   counts only accepted ones).
4. **AbuseIPDB client**, as in the Drupal module: key in a request header (never in URLs or logs); 2 s
   connect / 5 s total timeout; results cached 24 h per address; private and reserved addresses skipped;
   **fail open** (an error or timeout never blocks a visitor); after a 401 or 429, lookups pause
   (circuit breaker, honouring `Retry-After`, 1 min–24 h) so an attacker can't exhaust the quota to slow
   every form down. Free plan: 1,000 checks a day (3,000 for verified webmasters).
5. **No locking yourself out** *(user)*: the dashboard refuses to ban, blacklist or flag the admin's
   current address or a whitelisted one; automatic actions skip whitelisted addresses. If you're locked
   out anyway (say your address changed and someone banned the new one), recovery needs no database
   editing: the environment variable `IPGUARD_DISABLE=1` turns all blocking off until you fix the lists.
6. **The visitor's real address**: only from the configured trusted proxy (our Caddy container) via
   `X-Forwarded-For`, else Astro's `clientAddress`. A forged header from anyone else is ignored. An
   address that is itself a trusted proxy (loopback, the Docker network) is **never counted, flagged or
   banned**: a request without a forwarded address looks like the proxy's own, and judging it would
   block every visitor (found while testing webforms, 2026-10-20).
7. **Dashboard → IP Guard** (admins only): Flagged (the review queue), Blacklist, Banned, Whitelist,
   Settings (on/off, rate limit, threshold, block message; AbuseIPDB key write-only, or from the
   `ABUSEIPDB_API_KEY` environment variable, which wins), and **Check an address**: what each step would
   decide for an address and why (the Drupal module's `pipeline-report`). The block message never says
   why a submission was refused.
8. **Storage**: StudioCMS's plugin data table (one row per entry, plus short-lived rate-limit counters),
   re-validated on read. Old counters and expired entries are removed lazily during requests, at most
   once an hour (StudioCMS has no cron). Addresses stay only as long as they're needed: counters for the
   rate-limit window; list entries until removed or expired.
9. **For other plugins**: `checkAction(context, { kind: 'form', key })` returns `allow`, `refuse` or
   `flagged`; `recordAttempt(...)` counts rejected attempts. Webforms detects the plugin and calls these.

## Consequences

- Sites send visitor addresses to AbuseIPDB only when a key is set; their privacy policy should say so
  (spam prevention as a legitimate interest).
- One more middleware on every request (the ban check): one indexed lookup, cached per address.
- Tests: unit tests for the decision table, CIDR/IPv6 matching and the client's failure paths (mocked
  API); browser tests for the review actions, a ban, the self-lockout guard and the whitelist.
