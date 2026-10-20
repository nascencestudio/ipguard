/**
 * The dashboard's form actions as data (ADR 0001 §7): parsing what an admin submitted, and the error
 * codes the dashboard explains. Pure; the endpoint (runtime/admin-endpoint.ts) applies the results.
 */
import { type Cidr, parseCidr } from './ip.js';
import { LIMITS, type ListName, oneLine, parseSettings, type Settings, WINDOWS } from './model.js';

export const ERRORS = {
	'bad-range': 'That isn’t a valid address or range (e.g. 203.0.113.7, 203.0.113.0/24 or 2001:db8::/48).',
	'too-broad': 'That range is too broad (IPv4 at least /8, IPv6 at least /16).',
	'bad-date': 'The expiry date must be a valid date in the future.',
	exists: 'That address or range is already on this list.',
	'own-address': 'That includes your own current address: you would lock yourself out.',
	whitelisted: 'That includes a whitelisted address. Remove it from the whitelist first.',
	'nothing-selected': 'Nothing was selected.',
	'bad-settings': 'Some settings weren’t valid; nothing was saved.',
	'bad-key': 'An AbuseIPDB key has only letters and digits.',
	unknown: 'Unknown action.',
	failed: 'That didn’t work. Please try again.',
} as const;
export type AdminError = keyof typeof ERRORS;

/** Ranges broader than this aren't accepted (no banning half the internet by a typo). */
const MIN_PREFIX = { 4: 8, 6: 16 } as const;

export interface AddRequest {
	list: ListName;
	range: Cidr;
	reason: string;
	/** Blacklist only: ISO time the block ends (end of that day, UTC), or null. */
	expiresAt: string | null;
}

const LIST_NAMES: readonly ListName[] = ['whitelist', 'flagged', 'blacklist', 'banned'];
const isList = (v: unknown): v is ListName => LIST_NAMES.includes(v as ListName);

/** "Add an address" → a request, or why not. Flagged entries are only made automatically. */
export function parseAdd(form: FormData, now = Date.now()): AddRequest | { error: AdminError } {
	const list = form.get('list');
	if (!isList(list) || list === 'flagged') return { error: 'unknown' };
	const range = parseCidr(form.get('range'));
	if (!range) return { error: 'bad-range' };
	if (range.prefix < MIN_PREFIX[range.version]) return { error: 'too-broad' };
	let expiresAt: string | null = null;
	const expires = form.get('expires');
	if (list === 'blacklist' && typeof expires === 'string' && expires !== '') {
		if (!/^\d{4}-\d{2}-\d{2}$/.test(expires)) return { error: 'bad-date' };
		const end = Date.parse(`${expires}T23:59:59Z`);
		if (Number.isNaN(end) || end <= now) return { error: 'bad-date' };
		expiresAt = new Date(end).toISOString();
	}
	return { list, range, reason: oneLine(form.get('reason'), LIMITS.reason), expiresAt };
}

/** Selected entry ids (checkboxes named `ids`, or one row's button value), at most 500. */
export function selectedIds(form: FormData): string[] {
	return [
		...new Set(
			form
				.getAll('ids')
				.filter((v): v is string => typeof v === 'string' && /^ig_[a-z0-9]{16}$/.test(v))
				.slice(0, 500),
		),
	];
}

/**
 * The settings form → new settings, or an error. The key: a new one replaces the saved one; empty keeps
 * it; "clear" removes it.
 */
export function parseSettingsForm(form: FormData, current: Settings): Settings | { error: AdminError } {
	const num = (name: string) => {
		const raw = form.get(name);
		return typeof raw === 'string' && /^\d{1,6}$/.test(raw) ? Number(raw) : Number.NaN;
	};
	const maxAttempts = num('maxAttempts');
	const windowSeconds = num('windowSeconds');
	const minScore = num('minScore');
	const blockMessage = oneLine(form.get('blockMessage'), LIMITS.blockMessage);
	if (
		!(maxAttempts >= 1 && maxAttempts <= 1000) ||
		!WINDOWS.includes(windowSeconds as (typeof WINDOWS)[number]) ||
		!(minScore >= 0 && minScore <= 100) ||
		!blockMessage
	) {
		return { error: 'bad-settings' };
	}
	const typedKey = String(form.get('apiKey') ?? '').trim();
	if (typedKey && !/^[A-Za-z0-9]{1,200}$/.test(typedKey)) return { error: 'bad-key' };
	const apiKey = typedKey || (form.get('clearKey') === 'on' ? '' : current.apiKey);
	return parseSettings({
		enabled: form.get('enabled') === 'on',
		maxAttempts,
		windowSeconds,
		minScore,
		blockMessage,
		apiKey,
	});
}
