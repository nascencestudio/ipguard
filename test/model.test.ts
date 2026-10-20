import { describe, expect, it } from 'vitest';
import { type Cidr, type Ip, parseCidr, parseIp } from '../src/ip.js';
import {
	DEFAULT_SETTINGS,
	decide,
	type Entry,
	indexEntries,
	type ListName,
	listsOf,
	parseEntry,
	parseSettings,
	rangesOverlap,
	refusalFor,
} from '../src/model.js';

const ip = (text: string) => parseIp(text) as Ip;
const cidr = (text: string) => parseCidr(text) as Cidr;
let n = 0;
const entry = (list: ListName, range: string, extra: Partial<Entry> = {}): Entry => ({
	id: `ig_${String(n++).padStart(16, '0')}`,
	list,
	range,
	reason: 'test',
	source: 'manual',
	createdAt: '2026-10-19T00:00:00.000Z',
	createdBy: 'admin',
	...extra,
});
const NOW = Date.parse('2026-10-19T12:00:00Z');
const none = { whitelist: null, flagged: null, blacklist: null, banned: null };

describe('entries', () => {
	it('keeps a valid entry and canonicalises its range', () => {
		const raw = entry('blacklist', '2001:DB8:0:0::1', {
			score: 80,
			source: 'abuseipdb',
			expiresAt: '2026-11-01T00:00:00Z',
		});
		expect(parseEntry(raw)).toEqual({ ...raw, range: '2001:db8::1', expiresAt: '2026-11-01T00:00:00.000Z' });
	});

	it('refuses or cleans what isn’t valid', () => {
		expect(parseEntry(null)).toBeNull();
		expect(parseEntry(entry('blacklist', 'not an ip'))).toBeNull();
		expect(parseEntry({ ...entry('blacklist', '1.2.3.4'), id: '../x' })).toBeNull();
		expect(parseEntry({ ...entry('blacklist', '1.2.3.4'), list: 'vip' })).toBeNull();
		expect(parseEntry({ ...entry('blacklist', '1.2.3.4'), createdAt: 'yesterday' })).toBeNull();
		const cleaned = parseEntry({
			...entry('flagged', '1.2.3.4'),
			reason: 'line\nbreak<script>',
			score: 101,
			source: 'magic',
			expiresAt: '2030-01-01',
			extra: 'dropped',
		});
		expect(cleaned).toMatchObject({ reason: 'line break<script>', source: 'manual' });
		expect(cleaned).not.toHaveProperty('score');
		expect(cleaned).not.toHaveProperty('expiresAt');
		expect(cleaned).not.toHaveProperty('extra');
	});

	it('reads settings, falling back to defaults', () => {
		expect(parseSettings(null)).toEqual(DEFAULT_SETTINGS);
		expect(
			parseSettings({ maxAttempts: 0, windowSeconds: 123, minScore: 150, blockMessage: '  ', apiKey: 'a b' }),
		).toEqual(DEFAULT_SETTINGS);
		expect(
			parseSettings({ enabled: false, maxAttempts: 3, windowSeconds: 900, minScore: 90, apiKey: 'abc123' }),
		).toMatchObject({
			enabled: false,
			maxAttempts: 3,
			windowSeconds: 900,
			minScore: 90,
			apiKey: 'abc123',
		});
	});
});

describe('which lists an address is on', () => {
	const entries = indexEntries([
		entry('whitelist', '198.51.100.0/24'),
		entry('banned', '203.0.113.7'),
		entry('blacklist', '192.0.2.0/24', { expiresAt: '2026-10-19T11:00:00Z' }),
		entry('blacklist', '192.0.2.5', { expiresAt: '2026-10-20T00:00:00Z' }),
		entry('flagged', '2001:db8:1:2::/64'),
	]);

	it('matches ranges and single addresses, ignoring expired blacklist entries', () => {
		expect(listsOf(entries, ip('198.51.100.9'), NOW).whitelist?.range).toBe('198.51.100.0/24');
		expect(listsOf(entries, ip('203.0.113.7'), NOW).banned).not.toBeNull();
		expect(listsOf(entries, ip('192.0.2.9'), NOW).blacklist).toBeNull();
		expect(listsOf(entries, ip('192.0.2.5'), NOW).blacklist?.range).toBe('192.0.2.5');
		expect(listsOf(entries, ip('2001:db8:1:2:dead:beef::1'), NOW).flagged).not.toBeNull();
		expect(listsOf(entries, ip('8.8.8.8'), NOW)).toEqual(none);
	});
});

describe('the decision (ADR 0001 §3)', () => {
	const settings = { maxAttempts: 5, minScore: 75 };
	const on = (list: ListName) => ({ ...none, [list]: indexEntries([entry(list, '1.2.3.4')])[0] });

	it('whitelisted: always allowed, whatever else is true', () => {
		expect(
			decide({ on: { ...on('whitelist'), banned: on('banned').banned }, attempts: 99, score: 100, settings }),
		).toEqual({
			action: 'allow',
		});
	});

	it('banned, blacklisted or flagged: refused (flagged stays blocked until reviewed)', () => {
		expect(decide({ on: on('banned'), attempts: 0, score: null, settings })).toEqual({
			action: 'refuse',
			because: 'banned',
		});
		expect(decide({ on: on('blacklist'), attempts: 0, score: null, settings })).toEqual({
			action: 'refuse',
			because: 'blacklist',
		});
		expect(decide({ on: on('flagged'), attempts: 0, score: null, settings })).toEqual({
			action: 'refuse',
			because: 'flagged',
		});
	});

	it('abusive and over the limit: ban; abusive: blacklist; over the limit: flag; else allow', () => {
		expect(decide({ on: none, attempts: 5, score: 75, settings })).toEqual({ action: 'ban' });
		expect(decide({ on: none, attempts: 4, score: 90, settings })).toEqual({ action: 'blacklist' });
		expect(decide({ on: none, attempts: 5, score: 74, settings })).toEqual({ action: 'flag' });
		expect(decide({ on: none, attempts: 5, score: null, settings })).toEqual({ action: 'flag' });
		expect(decide({ on: none, attempts: 4, score: 74, settings })).toEqual({ action: 'allow' });
		expect(decide({ on: none, attempts: 0, score: null, settings })).toEqual({ action: 'allow' });
	});
});

describe('no locking yourself out (ADR 0001 §5)', () => {
	const entries = indexEntries([entry('whitelist', '198.51.100.10')]);

	it('refuses ranges with the admin’s own address or a whitelisted one', () => {
		const context = { adminIp: ip('192.0.2.50'), entries };
		expect(refusalFor('banned', cidr('192.0.2.0/24'), context)).toMatchObject({ code: 'own-address' });
		expect(refusalFor('blacklist', cidr('0.0.0.0/0'), context)).toMatchObject({ code: 'own-address' });
		expect(refusalFor('banned', cidr('198.51.100.0/24'), context)).toMatchObject({
			code: 'whitelisted',
			message: expect.stringContaining('198.51.100.10'),
		});
		expect(refusalFor('flagged', cidr('198.51.100.10'), context)).toMatchObject({ code: 'whitelisted' });
		expect(refusalFor('banned', cidr('203.0.113.0/24'), context)).toBeNull();
		expect(refusalFor('whitelist', cidr('192.0.2.50'), context)).toBeNull();
		expect(refusalFor('banned', cidr('192.0.2.0/24'), { adminIp: null, entries: [] })).toBeNull();
	});

	it('knows when ranges overlap', () => {
		expect(rangesOverlap(cidr('10.0.0.0/8'), cidr('10.1.2.3'))).toBe(true);
		expect(rangesOverlap(cidr('10.1.2.3'), cidr('10.0.0.0/8'))).toBe(true);
		expect(rangesOverlap(cidr('10.0.0.0/8'), cidr('11.0.0.0/8'))).toBe(false);
		expect(rangesOverlap(cidr('::/0'), cidr('10.0.0.0/8'))).toBe(false);
	});
});
