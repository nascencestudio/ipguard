import { describe, expect, it } from 'vitest';
import { createAbuseIpDb, ENDPOINT, type ScoreStore } from '../src/abuseipdb.js';
import { type Ip, parseIp } from '../src/ip.js';

const ip = (text: string) => parseIp(text) as Ip;
const KEY = 'secretkey123';

function setup(responses: Array<Response | Error>) {
	let time = Date.parse('2026-10-19T12:00:00Z');
	const scores = new Map<string, { score: number; expiresAt: number }>();
	let backoff: number | null = null;
	const store: ScoreStore = {
		getScore: async (a) => {
			const hit = scores.get(a);
			return hit && hit.expiresAt > time ? hit.score : null;
		},
		setScore: async (a, score, expiresAt) => void scores.set(a, { score, expiresAt }),
		getBackoff: async () => backoff,
		setBackoff: async (until) => {
			backoff = until;
		},
	};
	const calls: Array<{ url: string; init: RequestInit }> = [];
	const logs: string[] = [];
	const fetch = (async (url: string, init: RequestInit) => {
		calls.push({ url, init });
		const next = responses.shift();
		if (!next) throw new Error('unexpected request');
		if (next instanceof Error) throw next;
		return next;
	}) as unknown as typeof globalThis.fetch;
	const client = createAbuseIpDb({ fetch, store, now: () => time, log: (_, m) => logs.push(m) });
	return { client, calls, logs, advance: (ms: number) => (time += ms), backoff: () => backoff };
}
const ok = (score: unknown) => new Response(JSON.stringify({ data: { abuseConfidenceScore: score } }), { status: 200 });

describe('AbuseIPDB', () => {
	it('asks with the key in a header, then caches the score for 24 hours', async () => {
		const t = setup([ok(88), ok(10)]);
		expect(await t.client.check(ip('8.8.8.8'), KEY)).toEqual({ score: 88, cached: false });
		expect(t.calls[0]?.url).toBe(`${ENDPOINT}?ipAddress=8.8.8.8&maxAgeInDays=30`);
		expect(t.calls[0]?.init.headers).toEqual({ Key: KEY, Accept: 'application/json' });
		expect(t.calls[0]?.url).not.toContain(KEY);
		expect(await t.client.check(ip('8.8.8.8'), KEY)).toEqual({ score: 88, cached: true });
		t.advance(86_400_001);
		expect(await t.client.check(ip('8.8.8.8'), KEY)).toEqual({ score: 10, cached: false });
		expect(t.calls).toHaveLength(2);
	});

	it('never sends private or reserved addresses, and needs a key', async () => {
		const t = setup([]);
		expect(await t.client.check(ip('192.168.1.1'), KEY)).toEqual({ score: null, why: 'not-public' });
		expect(await t.client.check(ip('203.0.113.5'), KEY)).toEqual({ score: null, why: 'not-public' });
		expect(await t.client.check(ip('8.8.8.8'), '')).toEqual({ score: null, why: 'no-key' });
		expect(t.calls).toHaveLength(0);
	});

	it('fails open on errors, timeouts and nonsense, without logging the key', async () => {
		const t = setup([
			new Response('oops', { status: 500 }),
			new DOMException('timed out', 'TimeoutError'),
			new Response('<html>', { status: 200 }),
			ok(150),
			ok('80'),
		]);
		for (let i = 0; i < 5; i++)
			expect(await t.client.check(ip('1.1.1.1'), KEY)).toEqual({ score: null, why: 'failed' });
		expect(t.logs.join('\n')).not.toContain(KEY);
		expect(t.logs.some((l) => l.includes('TimeoutError'))).toBe(true);
	});

	it('pauses after 401 or 429, honouring Retry-After within 1 minute to 24 hours', async () => {
		const t = setup([new Response('', { status: 429, headers: { 'Retry-After': '120' } })]);
		expect(await t.client.check(ip('1.1.1.1'), KEY)).toEqual({ score: null, why: 'failed' });
		expect(await t.client.check(ip('9.9.9.9'), KEY)).toEqual({ score: null, why: 'paused' });
		expect(t.calls).toHaveLength(1);
		expect(await t.client.pausedUntil()).toBe(Date.parse('2026-10-19T12:02:00Z'));
		t.advance(120_001);
		expect(await t.client.pausedUntil()).toBeNull();

		const u = setup([new Response('', { status: 401 }), ok(5)]);
		await u.client.check(ip('1.1.1.1'), KEY);
		expect(u.backoff()).toBe(Date.parse('2026-10-19T13:00:00Z'));
		await u.client.resume();
		expect(await u.client.check(ip('1.1.1.1'), KEY)).toEqual({ score: 5, cached: false });

		const big = setup([new Response('', { status: 429, headers: { 'Retry-After': '999999' } })]);
		await big.client.check(ip('1.1.1.1'), KEY);
		expect(big.backoff()).toBe(Date.parse('2026-10-20T12:00:00Z'));
		const tiny = setup([new Response('', { status: 429, headers: { 'Retry-After': '1' } })]);
		await tiny.client.check(ip('1.1.1.1'), KEY);
		expect(tiny.backoff()).toBe(Date.parse('2026-10-19T12:01:00Z'));
	});

	it('checks IPv6 addresses in canonical form', async () => {
		const t = setup([ok(0)]);
		await t.client.check(ip('2606:4700:4700:0000:0000:0000:0000:1111'), KEY);
		expect(t.calls[0]?.url).toContain('ipAddress=2606%3A4700%3A4700%3A%3A1111');
	});
});
