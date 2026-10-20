# @nascencestudio/ipguard

**IP protection for [StudioCMS](https://studiocms.dev) sites:** review lists, rate limiting,
[AbuseIPDB](https://www.abuseipdb.com/) reputation checks and site-wide bans, managed in the dashboard.
Built for [@nascencestudio/webforms](https://github.com/nascencestudio/webforms), and usable by any plugin.

- **Four lists**, each entry a single address or a range (`203.0.113.0/24`, `2001:db8::/48`):
  - **Whitelist**: never checked, never blocked (your office, for testing).
  - **Flagged**: went over the rate limit; **blocked until you review it**: ban, blacklist, whitelist or
    dismiss.
  - **Blacklist**: can't submit forms; the site stays reachable. A block can end on a date.
  - **Banned**: gets "Access denied" for every page.
- **For each protected action** (a form submission): whitelisted → allowed; banned, blacklisted or
  flagged → refused; otherwise the rate limit and the AbuseIPDB score decide: a high score **and** over the
  limit → banned; a high score → blacklisted; over the limit → flagged; else allowed. IPv6 visitors are
  grouped by their /64.
- **AbuseIPDB done carefully:** the key travels in a header, lookups time out after 5 seconds, scores are
  kept 24 hours, private addresses are never sent, and if AbuseIPDB can't answer nobody is blocked. After a
  refused key or a used-up daily quota, lookups pause instead of slowing every form down.
- **You can't lock yourself out:** your own address and whitelisted ones can't be banned, blacklisted or
  flagged. If it happens anyway, `IPGUARD_DISABLE=1` turns all blocking off.
- **Check an address:** what would happen to a submission from an address, step by step.

## Requirements

- Node ≥ 22.12, Astro 7, StudioCMS 0.6 or 0.7

## Install

```sh
pnpm add @nascencestudio/ipguard
```

```js
// studiocms.config.mjs
import ipguard from '@nascencestudio/ipguard';
export default defineStudioCMSConfig({ plugins: [ipguard()] });
```

Then **Dashboard → Admin → IP Guard**. For AbuseIPDB, get a free key at
[abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) and set it as the `ABUSEIPDB_API_KEY`
environment variable (recommended), or in IP Guard's Settings. Mention the check in your privacy policy:
visitors' addresses are sent to AbuseIPDB when they submit a protected form.

**Behind a reverse proxy** (Caddy, nginx), IP Guard reads the visitor's address from `X-Forwarded-For`,
but only when the request comes from a trusted proxy. By default those are loopback and private
networks, which covers a proxy on the same machine or Docker network. Otherwise list yours:

```js
ipguard({ trustedProxies: ['10.0.0.5'] })
```

## For plugin authors

```ts
import { checkAction, recordAttempt } from '@nascencestudio/ipguard/guard';

const result = await checkAction(Astro, { key: 'form:contact' });
if (result.outcome === 'refuse') return new Response(result.message, { status: 403 });
// Something your own checks rejected (it counts towards the rate limit):
await recordAttempt(Astro);
```

## How it's built

IP Guard is developed with an AI coding assistant (Anthropic's Claude), directed by its maintainer at
Nascence Studio, who sets the requirements, makes the decisions and checks the results. Its design follows
the maintainer's own Drupal module. Commits written with the assistant's help say so (`Co-Authored-By`).

- **Decisions are written down** in [docs/decisions](docs/decisions/) and the [devlog](docs/devlog.md).
- **Behaviour is tested:** unit tests cover address parsing (IPv4, IPv6, ranges, forged headers), the
  decision table, the lockout guards and every AbuseIPDB failure path; browser tests in
  [tapestry-playground](https://github.com/nascencestudio/tapestry-playground) drive the dashboard, bans,
  flagging, reviews and an accessibility audit.
- **No runtime dependencies.** Releases are published from GitHub Actions with npm provenance and approved
  with two-factor authentication.

## License

MIT © Nascence Studio
