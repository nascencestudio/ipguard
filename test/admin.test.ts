import { describe, expect, it } from 'vitest';
import { parseAdd, parseSettingsForm, selectedIds } from '../src/admin.js';
import { formatCidr } from '../src/ip.js';
import { DEFAULT_SETTINGS } from '../src/model.js';

const form = (fields: Record<string, string | string[]>) => {
	const data = new FormData();
	for (const [k, v] of Object.entries(fields)) for (const one of [v].flat()) data.append(k, one);
	return data;
};
const NOW = Date.parse('2026-10-19T12:00:00Z');

describe('adding an address', () => {
	it('accepts addresses and ranges, canonical', () => {
		const added = parseAdd(form({ list: 'banned', range: ' 203.0.113.9/24 ', reason: 'Spam\nwave' }), NOW);
		if ('error' in added) throw new Error(added.error);
		expect(formatCidr(added.range)).toBe('203.0.113.0/24');
		expect(added).toMatchObject({ list: 'banned', reason: 'Spam wave', expiresAt: null });
	});

	it('refuses bad input, flagged entries and too-broad ranges', () => {
		expect(parseAdd(form({ list: 'flagged', range: '1.2.3.4' }), NOW)).toEqual({ error: 'unknown' });
		expect(parseAdd(form({ list: 'vip', range: '1.2.3.4' }), NOW)).toEqual({ error: 'unknown' });
		expect(parseAdd(form({ list: 'banned', range: 'evil.example' }), NOW)).toEqual({ error: 'bad-range' });
		expect(parseAdd(form({ list: 'banned', range: '10.0.0.0/7' }), NOW)).toEqual({ error: 'too-broad' });
		expect(parseAdd(form({ list: 'banned', range: '2001::/15' }), NOW)).toEqual({ error: 'too-broad' });
		expect('error' in parseAdd(form({ list: 'banned', range: '10.0.0.0/8' }), NOW)).toBe(false);
	});

	it('takes an expiry date for the blacklist only (end of that day, in the future)', () => {
		const added = parseAdd(form({ list: 'blacklist', range: '1.2.3.4', expires: '2026-10-25' }), NOW);
		expect(added).toMatchObject({ expiresAt: '2026-10-25T23:59:59.000Z' });
		expect(parseAdd(form({ list: 'blacklist', range: '1.2.3.4', expires: '2026-10-18' }), NOW)).toEqual({
			error: 'bad-date',
		});
		expect(parseAdd(form({ list: 'blacklist', range: '1.2.3.4', expires: 'tomorrow' }), NOW)).toEqual({
			error: 'bad-date',
		});
		expect(parseAdd(form({ list: 'banned', range: '1.2.3.4', expires: '2026-10-25' }), NOW)).toMatchObject({
			expiresAt: null,
		});
	});
});

describe('selected rows', () => {
	it('keeps valid, unique ids', () => {
		const id = 'ig_aaaaaaaaaaaaaaaa';
		expect(selectedIds(form({ ids: [id, id, '../etc', 'ig_short'] }))).toEqual([id]);
		expect(selectedIds(form({}))).toEqual([]);
	});
});

describe('settings', () => {
	const base = { maxAttempts: '5', windowSeconds: '3600', minScore: '75', blockMessage: 'No.' };

	it('saves valid settings; the key is replaced, kept or cleared', () => {
		const current = { ...DEFAULT_SETTINGS, apiKey: 'oldkey' };
		expect(parseSettingsForm(form({ ...base, enabled: 'on' }), current)).toMatchObject({
			enabled: true,
			apiKey: 'oldkey',
		});
		expect(parseSettingsForm(form({ ...base }), current)).toMatchObject({ enabled: false });
		expect(parseSettingsForm(form({ ...base, apiKey: 'newKey9' }), current)).toMatchObject({ apiKey: 'newKey9' });
		expect(parseSettingsForm(form({ ...base, clearKey: 'on' }), current)).toMatchObject({ apiKey: '' });
		expect(parseSettingsForm(form({ ...base, apiKey: 'newKey9', clearKey: 'on' }), current)).toMatchObject({
			apiKey: 'newKey9',
		});
	});

	it('refuses invalid values', () => {
		for (const bad of [
			{ maxAttempts: '0' },
			{ maxAttempts: 'many' },
			{ windowSeconds: '60' },
			{ minScore: '101' },
			{ blockMessage: '   ' },
		]) {
			expect(parseSettingsForm(form({ ...base, ...bad }), DEFAULT_SETTINGS), JSON.stringify(bad)).toEqual({
				error: 'bad-settings',
			});
		}
		expect(parseSettingsForm(form({ ...base, apiKey: 'key with spaces' }), DEFAULT_SETTINGS)).toEqual({
			error: 'bad-key',
		});
	});
});
