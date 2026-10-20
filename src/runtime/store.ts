/// <reference types="studiocms/v/types" />
/**
 * IP Guard's storage (ADR 0001 §8): rows in StudioCMS's plugin data table, each kind under its own key
 * prefix, re-validated on every read. Entries and settings are cached in memory for a few seconds (the
 * ban check runs on every request) and the cache is dropped on every write. Attempt counters keep the
 * times of recent attempts per subject (an IPv4 address or an IPv6 /64). Old counters, expired scores and
 * expired blacklist entries are removed lazily, at most once an hour (StudioCMS has no cron).
 * Straight through the SDK's database client (`usePluginData()` can't save in StudioCMS 0.6.1). Server only.
 */
import { randomBytes } from 'node:crypto';
import { runSDK, SDKCoreJs } from 'studiocms:sdk';
import type { ScoreStore } from '../abuseipdb.js';
import { type Entry, type IndexedEntry, indexEntries, parseEntry, parseSettings, type Settings } from '../model.js';

const P = '@nascencestudio/ipguard';
const ENTRY = `${P}-entry:`;
const ATTEMPTS = `${P}-attempts:`;
const SCORE = `${P}-score:`;
const SETTINGS_ROW = `${P}-settings`;
const STATE_ROW = `${P}-state`;
const CACHE_MS = 10_000;
const CLEANUP_MS = 3_600_000;

const db = () => SDKCoreJs.dbService.db;

interface Row {
	id: string;
	data: string;
}

async function rowsWithPrefix(prefix: string): Promise<Row[]> {
	// A range on the primary key instead of LIKE (no wildcards to escape).
	return db()
		.selectFrom('StudioCMSPluginData')
		.select(['id', 'data'])
		.where('id', '>=', prefix)
		.where('id', '<', `${prefix}￿`)
		.execute();
}

async function readRow(id: string): Promise<unknown> {
	const row = await db().selectFrom('StudioCMSPluginData').select('data').where('id', '=', id).executeTakeFirst();
	if (!row) return null;
	try {
		return JSON.parse(row.data) as unknown;
	} catch {
		return null;
	}
}

async function writeRow(id: string, value: unknown): Promise<void> {
	const data = JSON.stringify(value);
	await db()
		.transaction()
		.execute(async (trx) => {
			const existing = await trx.selectFrom('StudioCMSPluginData').select('id').where('id', '=', id).executeTakeFirst();
			if (existing) await trx.updateTable('StudioCMSPluginData').set({ data }).where('id', '=', id).execute();
			else await trx.insertInto('StudioCMSPluginData').values({ id, data }).execute();
		});
}

async function deleteRows(ids: readonly string[]): Promise<void> {
	if (ids.length === 0) return;
	await db().deleteFrom('StudioCMSPluginData').where('id', 'in', ids).execute();
}

const parseJson = (data: string): unknown => {
	try {
		return JSON.parse(data) as unknown;
	} catch {
		return null;
	}
};

// --- Entries ---------------------------------------------------------------------------------------

let entriesCache: { at: number; entries: IndexedEntry[] } | null = null;
let settingsCache: { at: number; settings: Settings } | null = null;

const dropCaches = () => {
	entriesCache = null;
	settingsCache = null;
	runSDK(SDKCoreJs.PLUGINS.clearPluginDataCache()).catch(() => {});
};

/** Every list entry, indexed for matching (cached for a few seconds). */
export async function loadEntries(): Promise<IndexedEntry[]> {
	if (entriesCache && Date.now() - entriesCache.at < CACHE_MS) return entriesCache.entries;
	const entries = (await rowsWithPrefix(ENTRY))
		.map((row) => parseEntry(parseJson(row.data)))
		.filter((entry): entry is Entry => entry !== null);
	entriesCache = { at: Date.now(), entries: indexEntries(entries) };
	return entriesCache.entries;
}

export const newEntryId = () => {
	const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return `ig_${[...randomBytes(16)].map((b) => alphabet[b % 36]).join('')}`;
};

export async function saveEntry(entry: Entry): Promise<void> {
	const clean = parseEntry(entry);
	if (!clean) throw new Error('invalid entry');
	await writeRow(`${ENTRY}${clean.id}`, clean);
	dropCaches();
}

export async function deleteEntries(ids: readonly string[]): Promise<void> {
	await deleteRows(ids.filter((id) => /^ig_[a-z0-9]{16}$/.test(id)).map((id) => `${ENTRY}${id}`));
	dropCaches();
}

// --- Settings --------------------------------------------------------------------------------------

export async function loadSettings(): Promise<Settings> {
	if (settingsCache && Date.now() - settingsCache.at < CACHE_MS) return settingsCache.settings;
	const settings = parseSettings(await readRow(SETTINGS_ROW).catch(() => null));
	settingsCache = { at: Date.now(), settings };
	return settings;
}

export async function saveSettings(settings: Settings): Promise<void> {
	await writeRow(SETTINGS_ROW, parseSettings(settings));
	dropCaches();
}

// --- Attempt counters ------------------------------------------------------------------------------

const attemptsId = (subject: string) => `${ATTEMPTS}${subject}`;

const timesOf = (value: unknown): number[] =>
	Array.isArray((value as { times?: unknown })?.times)
		? ((value as { times: unknown[] }).times.filter((t) => typeof t === 'number' && Number.isFinite(t)) as number[])
		: [];

/** Attempts by a subject within the window (seconds). */
export async function countAttempts(subject: string, windowSeconds: number, now = Date.now()): Promise<number> {
	const since = now - windowSeconds * 1000;
	return timesOf(await readRow(attemptsId(subject))).filter((t) => t > since).length;
}

/** Count one more attempt (old ones are dropped; at most 1,000 kept). */
export async function addAttempt(subject: string, windowSeconds: number, now = Date.now()): Promise<number> {
	const since = now - windowSeconds * 1000;
	const times = [...timesOf(await readRow(attemptsId(subject))).filter((t) => t > since), now].slice(-1000);
	await writeRow(attemptsId(subject), { times });
	return times.length;
}

export async function clearAttempts(subject: string): Promise<void> {
	await deleteRows([attemptsId(subject)]);
}

// --- AbuseIPDB cache and pause ---------------------------------------------------------------------

async function readState(): Promise<{ backoffUntil: number; lastCleanup: number }> {
	const raw = (await readRow(STATE_ROW).catch(() => null)) as Record<string, unknown> | null;
	const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
	return { backoffUntil: num(raw?.backoffUntil), lastCleanup: num(raw?.lastCleanup) };
}

export const scoreStore: ScoreStore = {
	async getScore(ip) {
		const raw = (await readRow(`${SCORE}${ip}`)) as { score?: unknown; expiresAt?: unknown } | null;
		if (!raw || typeof raw.score !== 'number' || typeof raw.expiresAt !== 'number') return null;
		return raw.expiresAt > Date.now() ? raw.score : null;
	},
	async setScore(ip, score, expiresAt) {
		await writeRow(`${SCORE}${ip}`, { score, expiresAt });
	},
	async getBackoff() {
		const { backoffUntil } = await readState();
		return backoffUntil > 0 ? backoffUntil : null;
	},
	async setBackoff(until) {
		await writeRow(STATE_ROW, { ...(await readState()), backoffUntil: until });
	},
};

export async function forgetScore(ip: string): Promise<void> {
	await deleteRows([`${SCORE}${ip}`]);
}

// --- Cleanup ---------------------------------------------------------------------------------------

/**
 * At most once an hour: drop counters with no attempt inside the longest window, expired scores and
 * expired blacklist entries. Errors are logged and ignored (it runs inside a visitor's request).
 */
export async function maybeCleanup(windowSeconds: number, now = Date.now()): Promise<void> {
	try {
		const state = await readState();
		if (now - state.lastCleanup < CLEANUP_MS) return;
		await writeRow(STATE_ROW, { ...state, lastCleanup: now });
		const since = now - windowSeconds * 1000;
		const stale: string[] = [];
		for (const row of await rowsWithPrefix(ATTEMPTS)) {
			if (!timesOf(parseJson(row.data)).some((t) => t > since)) stale.push(row.id);
		}
		for (const row of await rowsWithPrefix(SCORE)) {
			const expiresAt = (parseJson(row.data) as { expiresAt?: unknown } | null)?.expiresAt;
			if (typeof expiresAt !== 'number' || expiresAt <= now) stale.push(row.id);
		}
		for (const entry of await loadEntries()) {
			if (entry.list === 'blacklist' && entry.expiresAt && Date.parse(entry.expiresAt) <= now) {
				stale.push(`${ENTRY}${entry.id}`);
			}
		}
		await deleteRows(stale);
		if (stale.some((id) => id.startsWith(ENTRY))) dropCaches();
	} catch (error) {
		console.warn('[ipguard] cleanup failed', error);
	}
}
