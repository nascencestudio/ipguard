/**
 * The AbuseIPDB client (ADR 0001 §4), after the user's Drupal module: the key goes in a request header
 * (never in a URL or a log), requests time out after 5 seconds, scores are cached for 24 hours per
 * address, private and reserved addresses are never sent, and every failure returns null: **fail open**,
 * the caller doesn't block. After a 401 (bad key) or 429 (daily quota used up) lookups pause for the
 * `Retry-After` time (1 minute to 24 hours; 1 hour without one), so an attacker can't burn the quota to
 * slow every form down. The network and the cache are passed in (tests use fakes).
 */
import { formatIp, type Ip, isPublic } from './ip.js';

export const ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
export const CACHE_SECONDS = 86_400;
const MAX_AGE_DAYS = 30;
const TIMEOUT_MS = 5000;
const BACKOFF_DEFAULT = 3600;
const BACKOFF_MIN = 60;
const BACKOFF_MAX = 86_400;

export interface ScoreStore {
	/** A cached score that hasn't expired, or null. */
	getScore(ip: string): Promise<number | null>;
	setScore(ip: string, score: number, expiresAt: number): Promise<void>;
	/** When the pause ends (ms), or null. */
	getBackoff(): Promise<number | null>;
	setBackoff(until: number): Promise<void>;
}

export interface AbuseIpDbOptions {
	fetch: typeof globalThis.fetch;
	store: ScoreStore;
	now?: () => number;
	endpoint?: string;
	log?: (level: 'warn' | 'error', message: string) => void;
}

export type CheckResult =
	| { score: number; cached: boolean }
	| { score: null; why: 'not-public' | 'no-key' | 'paused' | 'failed' };

export function createAbuseIpDb(options: AbuseIpDbOptions) {
	const now = options.now ?? Date.now;
	const endpoint = options.endpoint ?? ENDPOINT;
	const log = options.log ?? ((level, message) => console[level](`[ipguard] ${message}`));

	async function pause(retryAfter: string | null): Promise<void> {
		const seconds = retryAfter && /^[0-9]{1,6}$/.test(retryAfter) ? Number(retryAfter) : BACKOFF_DEFAULT;
		const clamped = Math.max(BACKOFF_MIN, Math.min(seconds, BACKOFF_MAX));
		await options.store.setBackoff(now() + clamped * 1000);
		log('warn', `AbuseIPDB lookups paused for ${clamped} s; forms aren't blocked by AbuseIPDB meanwhile.`);
	}

	/** The address's abuse confidence score (0–100), or why there's none. */
	async function check(ip: Ip, apiKey: string): Promise<CheckResult> {
		if (!isPublic(ip)) return { score: null, why: 'not-public' };
		const address = formatIp(ip);
		const cached = await options.store.getScore(address).catch(() => null);
		if (cached !== null) return { score: cached, cached: true };
		if (!apiKey) return { score: null, why: 'no-key' };
		const until = await options.store.getBackoff().catch(() => null);
		if (until !== null && until > now()) return { score: null, why: 'paused' };

		const url = `${endpoint}?${new URLSearchParams({ ipAddress: address, maxAgeInDays: String(MAX_AGE_DAYS) })}`;
		try {
			const response = await options.fetch(url, {
				headers: { Key: apiKey, Accept: 'application/json' },
				signal: AbortSignal.timeout(TIMEOUT_MS),
				redirect: 'error',
			});
			if (response.status === 401 || response.status === 429) {
				log(
					'warn',
					response.status === 401
						? 'AbuseIPDB refused the API key (HTTP 401): check it in IP Guard settings.'
						: 'AbuseIPDB daily limit reached (HTTP 429).',
				);
				await pause(response.headers.get('retry-after'));
				return { score: null, why: 'failed' };
			}
			if (!response.ok) {
				log('warn', `AbuseIPDB answered HTTP ${response.status} for ${address}.`);
				return { score: null, why: 'failed' };
			}
			const body = (await response.json()) as { data?: { abuseConfidenceScore?: unknown } };
			const score = body?.data?.abuseConfidenceScore;
			if (typeof score !== 'number' || !Number.isInteger(score) || score < 0 || score > 100) {
				log('warn', `AbuseIPDB sent no valid score for ${address}.`);
				return { score: null, why: 'failed' };
			}
			await options.store.setScore(address, score, now() + CACHE_SECONDS * 1000).catch(() => {});
			return { score, cached: false };
		} catch (error) {
			// Timeouts, network errors, non-JSON bodies. The message never contains the key.
			log('error', `AbuseIPDB lookup for ${address} failed: ${(error as Error).name}`);
			return { score: null, why: 'failed' };
		}
	}

	return {
		check,
		/** When paused lookups resume (ms), or null. */
		pausedUntil: async () => {
			const until = await options.store.getBackoff().catch(() => null);
			return until !== null && until > now() ? until : null;
		},
		/** Resume lookups now (after fixing the key, or a new day's quota). */
		resume: () => options.store.setBackoff(0),
	};
}

export type AbuseIpDb = ReturnType<typeof createAbuseIpDb>;
