/**
 * Site-wide bans (ADR 0001 §2): every request from a banned address gets a bare 403 before anything else
 * runs (no page, no session). Whitelisted addresses are never banned. Fails open: if the lists can't be
 * read, the request goes through.
 */
import type { MiddlewareHandler } from 'astro';
import { listsOf } from '../model.js';
import { clientIp, disabledByEnvironment } from './guard.js';
import { loadEntries, loadSettings } from './store.js';

export const onRequest: MiddlewareHandler = async (context, next) => {
	if (disabledByEnvironment()) return next();
	try {
		const ip = clientIp(context);
		if (ip && (await loadSettings()).enabled) {
			const entries = await loadEntries();
			if (entries.some((e) => e.list === 'banned')) {
				const on = listsOf(entries, ip, Date.now());
				if (on.banned && !on.whitelist) {
					return new Response('Access denied.', {
						status: 403,
						headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
					});
				}
			}
		}
	} catch (error) {
		console.warn('[ipguard] ban check failed; letting the request through', error);
	}
	return next();
};
