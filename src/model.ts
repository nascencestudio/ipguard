/**
 * IP Guard's model (ADR 0001): list entries, settings and the decision for an action. Everything read
 * from storage or received from a form is validated again here. Pure.
 */
import { type Cidr, cidrContains, formatCidr, type Ip, parseCidr } from './ip.js';

export const LISTS = ['whitelist', 'flagged', 'blacklist', 'banned'] as const;
export type ListName = (typeof LISTS)[number];
export const SOURCES = ['manual', 'abuseipdb', 'rate_limit'] as const;
export type Source = (typeof SOURCES)[number];

export const LIMITS = { reason: 255, note: 500, blockMessage: 512 } as const;
export const ENTRY_ID = /^ig_[a-z0-9]{16}$/;

export interface Entry {
	id: string;
	list: ListName;
	/** A single address or a range, canonical (`192.0.2.7`, `2001:db8:1:2::/64`). */
	range: string;
	reason: string;
	source: Source;
	/** The AbuseIPDB score when the source is AbuseIPDB. */
	score?: number;
	/** Attempts counted when an address was flagged. */
	count?: number;
	/** ISO time. */
	createdAt: string;
	/** Who added it (a user name), or null for automatic entries. */
	createdBy: string | null;
	/** Blacklist only: the block ends at this ISO time; null or absent: never. */
	expiresAt?: string | null;
}

export interface Settings {
	enabled: boolean;
	/** Attempts allowed per address within the window before it's flagged. */
	maxAttempts: number;
	windowSeconds: number;
	/** AbuseIPDB confidence score (0–100) at which an address is blacklisted. */
	minScore: number;
	/** What a refused visitor sees; never the reason. */
	blockMessage: string;
	/** The AbuseIPDB key saved in the dashboard (an environment variable wins). Empty: none. */
	apiKey: string;
}

export const WINDOWS = [300, 900, 1800, 3600, 7200, 21600, 43200, 86400] as const;

export const DEFAULT_SETTINGS: Settings = {
	enabled: true,
	maxAttempts: 5,
	windowSeconds: 3600,
	minScore: 75,
	blockMessage: 'Your submission could not be processed. Please contact us directly if you believe this is an error.',
	apiKey: '',
};

const isObject = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === 'object' && !Array.isArray(v);

/** One line of text: control characters become spaces, whitespace collapsed, trimmed, capped. */
export function oneLine(value: unknown, max: number): string {
	if (typeof value !== 'string') return '';
	let text = '';
	for (const char of value) text += (char.codePointAt(0) ?? 0) < 0x20 || char === '\u007f' ? ' ' : char;
	return text.replace(/\s+/g, ' ').trim().slice(0, max);
}

const isoTime = (value: unknown): string | null => {
	if (typeof value !== 'string' || value.length > 40) return null;
	const time = Date.parse(value);
	return Number.isNaN(time) ? null : new Date(time).toISOString();
};

const intIn = (value: unknown, min: number, max: number): number | null =>
	typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max ? value : null;

/** A stored or received entry (any JSON) → a valid entry, or null. */
export function parseEntry(raw: unknown): Entry | null {
	if (!isObject(raw)) return null;
	if (typeof raw.id !== 'string' || !ENTRY_ID.test(raw.id)) return null;
	if (!LISTS.includes(raw.list as ListName)) return null;
	const cidr = parseCidr(raw.range);
	const createdAt = isoTime(raw.createdAt);
	if (!cidr || !createdAt) return null;
	const entry: Entry = {
		id: raw.id,
		list: raw.list as ListName,
		range: formatCidr(cidr),
		reason: oneLine(raw.reason, LIMITS.reason),
		source: SOURCES.includes(raw.source as Source) ? (raw.source as Source) : 'manual',
		createdAt,
		createdBy: typeof raw.createdBy === 'string' ? oneLine(raw.createdBy, 100) || null : null,
	};
	const score = intIn(raw.score, 0, 100);
	if (score !== null) entry.score = score;
	const count = intIn(raw.count, 0, 1_000_000);
	if (count !== null) entry.count = count;
	if (entry.list === 'blacklist') entry.expiresAt = isoTime(raw.expiresAt);
	return entry;
}

/** Stored settings (any JSON) → valid settings; anything missing or invalid takes the default. */
export function parseSettings(raw: unknown): Settings {
	const r = isObject(raw) ? raw : {};
	return {
		enabled: typeof r.enabled === 'boolean' ? r.enabled : DEFAULT_SETTINGS.enabled,
		maxAttempts: intIn(r.maxAttempts, 1, 1000) ?? DEFAULT_SETTINGS.maxAttempts,
		windowSeconds: WINDOWS.includes(r.windowSeconds as (typeof WINDOWS)[number])
			? (r.windowSeconds as number)
			: DEFAULT_SETTINGS.windowSeconds,
		minScore: intIn(r.minScore, 0, 100) ?? DEFAULT_SETTINGS.minScore,
		blockMessage: oneLine(r.blockMessage, LIMITS.blockMessage) || DEFAULT_SETTINGS.blockMessage,
		apiKey: typeof r.apiKey === 'string' && /^[A-Za-z0-9]{1,200}$/.test(r.apiKey) ? r.apiKey : '',
	};
}

/** An entry with its range parsed, for matching. */
export interface IndexedEntry extends Entry {
	cidr: Cidr;
}

export const indexEntries = (entries: readonly Entry[]): IndexedEntry[] =>
	entries.flatMap((entry) => {
		const cidr = parseCidr(entry.range);
		return cidr ? [{ ...entry, cidr }] : [];
	});

const isActive = (entry: Entry, now: number) =>
	entry.list !== 'blacklist' || !entry.expiresAt || Date.parse(entry.expiresAt) > now;

/** The lists an address is on (active entries only; an expired blacklist entry doesn't count). */
export function listsOf(entries: readonly IndexedEntry[], ip: Ip, now: number): Record<ListName, IndexedEntry | null> {
	const found: Record<ListName, IndexedEntry | null> = {
		whitelist: null,
		flagged: null,
		blacklist: null,
		banned: null,
	};
	for (const entry of entries) {
		if (!found[entry.list] && isActive(entry, now) && cidrContains(entry.cidr, ip)) found[entry.list] = entry;
	}
	return found;
}

/** Whether two ranges share any address. */
export const rangesOverlap = (a: Cidr, b: Cidr) =>
	a.version === b.version &&
	(cidrContains(a, { version: b.version, value: b.network }) ||
		cidrContains(b, { version: a.version, value: a.network }));

export type Decision =
	| { action: 'allow' }
	| { action: 'refuse'; because: ListName }
	| { action: 'ban' | 'blacklist' | 'flag' };

/**
 * The decision for an action (ADR 0001 §3), given the lists the address is on, the attempts already
 * counted in the window, and the AbuseIPDB score (null: unknown, no key, or the API failed: fail open).
 * `ban`, `blacklist` and `flag` refuse this action too.
 */
export function decide(input: {
	on: Record<ListName, IndexedEntry | null>;
	attempts: number;
	score: number | null;
	settings: Pick<Settings, 'maxAttempts' | 'minScore'>;
}): Decision {
	const { on, attempts, score, settings } = input;
	if (on.whitelist) return { action: 'allow' };
	if (on.banned) return { action: 'refuse', because: 'banned' };
	if (on.blacklist) return { action: 'refuse', because: 'blacklist' };
	if (on.flagged) return { action: 'refuse', because: 'flagged' };
	const overLimit = attempts >= settings.maxAttempts;
	const abusive = score !== null && score >= settings.minScore;
	if (overLimit && abusive) return { action: 'ban' };
	if (abusive) return { action: 'blacklist' };
	if (overLimit) return { action: 'flag' };
	return { action: 'allow' };
}

export interface Refusal {
	code: 'own-address' | 'whitelisted';
	message: string;
}

/**
 * Why an admin can't put a range on a list (ADR 0001 §5), or null when it's fine: banning, blacklisting
 * or flagging the admin's own current address, or a whitelisted address.
 */
export function refusalFor(
	list: ListName,
	range: Cidr,
	context: { adminIp: Ip | null; entries: readonly IndexedEntry[] },
): Refusal | null {
	if (list === 'whitelist') return null;
	if (context.adminIp && cidrContains(range, context.adminIp)) {
		return { code: 'own-address', message: 'That includes your own current address: you would lock yourself out.' };
	}
	const whitelisted = context.entries.find((e) => e.list === 'whitelist' && rangesOverlap(e.cidr, range));
	if (whitelisted) {
		return {
			code: 'whitelisted',
			message: `That includes the whitelisted ${whitelisted.range}. Remove it from the whitelist first.`,
		};
	}
	return null;
}
