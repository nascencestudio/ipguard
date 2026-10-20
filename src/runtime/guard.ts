/// <reference types="studiocms/v/types" />
/// <reference path="../virtual.d.ts" />
/**
 * `@nascencestudio/ipguard/guard`: IP Guard for other plugins (ADR 0001 §3, §9). Webforms calls
 * `checkAction()` before accepting a submission and `recordAttempt()` for submissions its own spam checks
 * rejected. Server only.
 *
 * `IPGUARD_DISABLE=1` (environment) turns every check and ban off: the way back in after a lockout.
 */
import config from 'virtual:ipguard/config';
import { type AbuseIpDb, createAbuseIpDb } from '../abuseipdb.js';
import {
	type Cidr,
	formatCidr,
	formatIp,
	type Ip,
	isSingleAddress,
	parseCidr,
	resolveClientIp,
	subjectOf,
} from '../ip.js';
import {
	type Decision,
	type Entry,
	type IndexedEntry,
	type ListName,
	listsOf,
	rangesOverlap,
	type Settings,
	decide as tableDecision,
} from '../model.js';
import {
	addAttempt,
	countAttempts,
	loadEntries,
	loadSettings,
	maybeCleanup,
	newEntryId,
	saveEntry,
	scoreStore,
} from './store.js';

export type { Decision } from '../model.js';

/** What a request looks like to IP Guard (an Astro context or global). */
export interface RequestLike {
	request: Request;
	clientAddress?: string;
}

const trusted = config.trustedProxies.map(parseCidr).filter((c): c is Cidr => c !== null);

/** The off switch (environment): no checks, no bans. */
export const disabledByEnvironment = () => process.env.IPGUARD_DISABLE === '1';

/** The visitor's real address, or null (then nothing is checked: fail open). */
export function clientIp(context: RequestLike): Ip | null {
	let remote: string | undefined;
	try {
		remote = context.clientAddress;
	} catch {
		remote = undefined;
	}
	return resolveClientIp(remote, context.request.headers.get('x-forwarded-for'), trusted);
}

let client: AbuseIpDb | null = null;
export const abuseIpDb = () => {
	client ??= createAbuseIpDb({ fetch: globalThis.fetch, store: scoreStore, endpoint: config.abuseIpDbEndpoint });
	return client;
};

/** The AbuseIPDB key in use: the environment variable wins over the dashboard's. */
export const apiKeyOf = (settings: Settings) => process.env.ABUSEIPDB_API_KEY?.trim() || settings.apiKey;

/**
 * The range an automatic entry covers: the subject (an IPv4 address or an IPv6 /64), or just the address
 * when the /64 would also cover a whitelisted address (never act on whitelisted addresses).
 */
function automaticRange(ip: Ip, entries: readonly IndexedEntry[]): Cidr {
	const subject = subjectOf(ip);
	if (isSingleAddress(subject)) return subject;
	const touchesWhitelist = entries.some((e) => e.list === 'whitelist' && rangesOverlap(e.cidr, subject));
	return touchesWhitelist ? (parseCidr(formatIp(ip)) as Cidr) : subject;
}

async function addAutomatic(list: ListName, range: Cidr, reason: string, extra: Partial<Entry> = {}): Promise<void> {
	await saveEntry({
		id: newEntryId(),
		list,
		range: formatCidr(range),
		reason,
		source: 'manual',
		createdAt: new Date().toISOString(),
		createdBy: null,
		...extra,
	});
}

export interface CheckResult {
	/** `allow`: go ahead. `refuse`: show the block message (never the reason). */
	outcome: 'allow' | 'refuse';
	decision: Decision | { action: 'off' } | { action: 'unknown-address' };
	/** The message to show a refused visitor. */
	message: string;
}

/**
 * Check an action (a form submission) from this request: lists, rate limit, AbuseIPDB (ADR 0001 §3).
 * Acts on the decision (ban, blacklist or flag the subject) and counts allowed attempts.
 * `key` names what's protected (e.g. `form:contact`) for the log.
 */
export async function checkAction(context: RequestLike, options: { key: string }): Promise<CheckResult> {
	const settings = await loadSettings();
	const message = settings.blockMessage;
	if (!settings.enabled || disabledByEnvironment()) return { outcome: 'allow', decision: { action: 'off' }, message };
	const ip = clientIp(context);
	if (!ip) return { outcome: 'allow', decision: { action: 'unknown-address' }, message };

	const entries = await loadEntries();
	const now = Date.now();
	const on = listsOf(entries, ip, now);
	const subject = formatCidr(subjectOf(ip));
	const listed = on.whitelist || on.banned || on.blacklist || on.flagged;
	const attempts = listed ? 0 : await countAttempts(subject, settings.windowSeconds, now);
	const score = listed ? null : (await abuseIpDb().check(ip, apiKeyOf(settings))).score;
	const decision = tableDecision({ on, attempts, score, settings });
	const range = automaticRange(ip, entries);
	const where = `${formatIp(ip)} (${options.key.slice(0, 80)})`;

	switch (decision.action) {
		case 'ban':
			await addAutomatic('banned', range, `Over the rate limit and AbuseIPDB score ${score}%`, {
				source: 'abuseipdb',
				score: score ?? undefined,
			});
			await addAutomatic('blacklist', range, `Over the rate limit and AbuseIPDB score ${score}%`, {
				source: 'abuseipdb',
				score: score ?? undefined,
				expiresAt: null,
			});
			console.info(`[ipguard] banned ${where}`);
			break;
		case 'blacklist':
			await addAutomatic('blacklist', range, `AbuseIPDB score ${score}%`, {
				source: 'abuseipdb',
				score: score ?? undefined,
				expiresAt: null,
			});
			console.info(`[ipguard] blacklisted ${where}`);
			break;
		case 'flag':
			await addAutomatic('flagged', range, `Over the rate limit (${attempts} attempts)`, {
				source: 'rate_limit',
				count: attempts,
			});
			console.info(`[ipguard] flagged ${where}`);
			break;
		case 'allow':
			if (!on.whitelist) await addAttempt(subject, settings.windowSeconds, now);
			break;
		case 'refuse':
			break;
	}
	await maybeCleanup(settings.windowSeconds, now);
	return { outcome: decision.action === 'allow' ? 'allow' : 'refuse', decision, message };
}

/**
 * Count an attempt that was rejected before `checkAction()` (e.g. a form's honeypot caught it): it counts
 * towards the rate limit like an accepted one (ADR 0001 §3). Whitelisted addresses aren't counted.
 */
export async function recordAttempt(context: RequestLike): Promise<void> {
	const settings = await loadSettings();
	if (!settings.enabled || disabledByEnvironment()) return;
	const ip = clientIp(context);
	if (!ip) return;
	if (listsOf(await loadEntries(), ip, Date.now()).whitelist) return;
	await addAttempt(formatCidr(subjectOf(ip)), settings.windowSeconds);
}
