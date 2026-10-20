/// <reference types="studiocms/v/types" />
/**
 * `POST /_ipguard/admin`: the dashboard's forms (ADR 0001 §7). Admins only, same origin. Each form names
 * an `action` and where to go back (`return`, a path on this site); the answer redirects there with
 * `saved` or `error=<code>` (admin.ts). Every way of blocking an address goes through the lockout guard
 * (`refusalFor`): never the admin's own address, never a whitelisted one.
 */
import type { APIRoute } from 'astro';
import { type AdminError, parseAdd, parseSettingsForm, selectedIds } from '../admin.js';
import { formatCidr, formatIp, isSingleAddress, parseCidr, parseIp, subjectOf } from '../ip.js';
import { type Entry, type IndexedEntry, type ListName, refusalFor } from '../model.js';
import { abuseIpDb, apiKeyOf, clientIp } from './guard.js';
import {
	clearAttempts,
	deleteEntries,
	forgetScore,
	loadEntries,
	loadSettings,
	newEntryId,
	saveEntry,
	saveSettings,
} from './store.js';
import { getIpGuardViewer } from './viewer.js';

export const prerender = false;

const MAX_BODY = 64 * 1024;

const safeReturn = (value: unknown) =>
	typeof value === 'string' && /^\/(?!\/)[^\s\\]{0,500}$/.test(value) ? value : '/';

function redirect(back: string, outcome: { saved: true } | { error: AdminError } | { params: Record<string, string> }) {
	const url = new URL(back, 'http://x');
	url.searchParams.delete('saved');
	url.searchParams.delete('error');
	if ('saved' in outcome) url.searchParams.set('saved', '');
	else if ('error' in outcome) url.searchParams.set('error', outcome.error);
	else for (const [k, v] of Object.entries(outcome.params)) url.searchParams.set(k, v);
	return new Response(null, {
		status: 303,
		headers: { Location: `${url.pathname}${url.search}`, 'Cache-Control': 'no-store' },
	});
}

/** Why this range can't be blocked, as an error code, or null. */
function guard(
	list: ListName,
	range: IndexedEntry['cidr'],
	adminIp: ReturnType<typeof clientIp>,
	entries: IndexedEntry[],
) {
	return refusalFor(list, range, { adminIp, entries })?.code ?? null;
}

const entryFor = (
	list: ListName,
	range: string,
	reason: string,
	by: string | null,
	extra: Partial<Entry> = {},
): Entry => ({
	id: newEntryId(),
	list,
	range,
	reason,
	source: 'manual',
	createdAt: new Date().toISOString(),
	createdBy: by,
	...extra,
});

/** After a review, forget the flagged range's attempts, so a dismissed address can submit again. */
async function forgetAttempts(range: string) {
	await clearAttempts(range);
	const cidr = parseCidr(range);
	if (cidr && cidr.version === 6 && isSingleAddress(cidr)) {
		await clearAttempts(formatCidr(subjectOf({ version: 6, value: cidr.network })));
	}
}

export const POST: APIRoute = async (context) => {
	if (context.request.headers.get('origin') !== context.url.origin) {
		return new Response('Cross-origin request refused', { status: 403 });
	}
	const viewer = await getIpGuardViewer(context);
	if (!viewer.isAdmin) return new Response('Admins only', { status: 403 });
	if (Number(context.request.headers.get('content-length') ?? 0) > MAX_BODY) {
		return new Response('Too large', { status: 413 });
	}
	let form: FormData;
	try {
		form = await context.request.formData();
	} catch {
		return new Response('Bad form', { status: 400 });
	}
	const back = safeReturn(form.get('return'));
	const by = viewer.name ?? 'admin';
	const adminIp = clientIp(context);

	try {
		const entries = await loadEntries();
		const action = form.get('action');

		if (action === 'add') {
			const request = parseAdd(form);
			if ('error' in request) return redirect(back, request);
			const range = formatCidr(request.range);
			if (entries.some((e) => e.list === request.list && e.range === range)) return redirect(back, { error: 'exists' });
			const refused = guard(request.list, request.range, adminIp, entries);
			if (refused) return redirect(back, { error: refused });
			await saveEntry(
				entryFor(
					request.list,
					range,
					request.reason,
					by,
					request.list === 'blacklist' ? { expiresAt: request.expiresAt } : {},
				),
			);
			return redirect(back, { saved: true });
		}

		if (action === 'remove') {
			const ids = selectedIds(form);
			if (ids.length === 0) return redirect(back, { error: 'nothing-selected' });
			await deleteEntries(ids);
			return redirect(back, { saved: true });
		}

		// Flagged review: ban, blacklist, whitelist or dismiss the selected entries.
		if (action === 'review') {
			const op = form.get('op');
			const picked = entries.filter((e) => e.list === 'flagged' && selectedIds(form).includes(e.id));
			if (picked.length === 0) return redirect(back, { error: 'nothing-selected' });
			const lists: ListName[] =
				op === 'ban'
					? ['banned', 'blacklist']
					: op === 'blacklist'
						? ['blacklist']
						: op === 'whitelist'
							? ['whitelist']
							: [];
			if (op !== 'dismiss' && lists.length === 0) return redirect(back, { error: 'unknown' });
			for (const flag of picked) {
				for (const list of lists) {
					const refused = guard(list, flag.cidr, adminIp, entries);
					if (refused) return redirect(back, { error: refused });
				}
			}
			for (const flag of picked) {
				for (const list of lists) {
					if (entries.some((e) => e.list === list && e.range === flag.range)) continue;
					await saveEntry(
						entryFor(list, flag.range, `Flagged: ${flag.reason}`, by, list === 'blacklist' ? { expiresAt: null } : {}),
					);
				}
				await forgetAttempts(flag.range);
			}
			await deleteEntries(picked.map((e) => e.id));
			return redirect(back, { saved: true });
		}

		// Ban blacklisted entries (they stay on the blacklist).
		if (action === 'ban') {
			const picked = entries.filter((e) => e.list === 'blacklist' && selectedIds(form).includes(e.id));
			if (picked.length === 0) return redirect(back, { error: 'nothing-selected' });
			for (const entry of picked) {
				const refused = guard('banned', entry.cidr, adminIp, entries);
				if (refused) return redirect(back, { error: refused });
			}
			for (const entry of picked) {
				if (!entries.some((e) => e.list === 'banned' && e.range === entry.range)) {
					await saveEntry(entryFor('banned', entry.range, entry.reason || 'From the blacklist', by));
				}
			}
			return redirect(back, { saved: true });
		}

		if (action === 'settings') {
			const settings = parseSettingsForm(form, await loadSettings());
			if ('error' in settings) return redirect(back, settings);
			await saveSettings(settings);
			return redirect(back, { saved: true });
		}

		if (action === 'resume') {
			await abuseIpDb().resume();
			return redirect(back, { saved: true });
		}

		// "Check an address": ask AbuseIPDB now (uses one lookup; the answer is cached for the report).
		if (action === 'lookup') {
			const ip = parseIp(form.get('ip'));
			if (!ip) return redirect(back, { error: 'bad-range' });
			await forgetScore(formatIp(ip));
			await abuseIpDb().check(ip, apiKeyOf(await loadSettings()));
			return redirect(back, { params: { view: 'check', ip: formatIp(ip), looked: '' } });
		}

		return redirect(back, { error: 'unknown' });
	} catch (error) {
		console.error('[ipguard] admin action failed', error);
		return redirect(back, { error: 'failed' });
	}
};
