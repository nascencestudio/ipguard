/**
 * @nascencestudio/ipguard: IP protection for StudioCMS sites (ADR 0001).
 * - Review lists: whitelist, flagged (blocked until reviewed), blacklist (with expiry), banned (every
 *   request refused); single addresses or ranges.
 * - Rate limiting and AbuseIPDB reputation checks for protected actions, through
 *   `@nascencestudio/ipguard/guard` (webforms uses it).
 * - Dashboard → IP Guard (admins): the lists, settings, and a check of what happens to an address.
 * `IPGUARD_DISABLE=1` turns all blocking off (the way back in after a lockout).
 */
import { fileURLToPath } from 'node:url';
import { definePlugin } from 'studiocms/plugins';
import { ENDPOINT } from './abuseipdb.js';
import { DEFAULT_TRUSTED_PROXIES, parseCidr } from './ip.js';

export type { CheckResult as AbuseIpDbResult } from './abuseipdb.js';
export type { Cidr, Ip } from './ip.js';
export { cidrContains, formatCidr, formatIp, isPublic, parseCidr, parseIp, resolveClientIp, subjectOf } from './ip.js';
export type { Decision, Entry, ListName, Settings } from './model.js';
export { DEFAULT_SETTINGS, decide, parseEntry, parseSettings } from './model.js';

const PACKAGE_NAME = '@nascencestudio/ipguard';
const CONFIG_MODULE = 'virtual:ipguard/config';
/** StudioCMS names a plugin page's address from its identifier (`/` and `-` become `_`). */
export const DASHBOARD_PAGE = 'nascencestudio_ipguard/ipguard';
export const ADMIN_ROUTE = '/_ipguard/admin';

export interface IpGuardOptions {
	/**
	 * Proxies whose `X-Forwarded-For` is believed, as addresses or CIDR ranges. Default: loopback and
	 * private networks, where a reverse proxy (e.g. Caddy in Docker) runs. Requests from anywhere else
	 * use their connecting address, whatever headers they send.
	 */
	trustedProxies?: string[];
	/** The AbuseIPDB endpoint (only for tests with a local fake; https unless on localhost). */
	abuseIpDbEndpoint?: string;
}

export type IpGuardPlugin = ReturnType<typeof definePlugin>;

const resolve = (path: string) => fileURLToPath(new URL(path, import.meta.url));

function checkOptions(options: IpGuardOptions) {
	const trustedProxies = options.trustedProxies ?? DEFAULT_TRUSTED_PROXIES;
	for (const range of trustedProxies) {
		if (!parseCidr(range)) throw new Error(`[ipguard] trustedProxies: "${range}" isn't an address or CIDR range.`);
	}
	const endpoint = options.abuseIpDbEndpoint ?? ENDPOINT;
	const url = URL.canParse(endpoint) ? new URL(endpoint) : null;
	const local = url && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
	if (!url || !(url.protocol === 'https:' || (url.protocol === 'http:' && local))) {
		throw new Error('[ipguard] abuseIpDbEndpoint must be an https address (http only on localhost).');
	}
	return { trustedProxies, abuseIpDbEndpoint: endpoint, dashboardPage: DASHBOARD_PAGE };
}

/**
 * The IP Guard plugin.
 *
 * @example
 * ```js
 * // studiocms.config.mjs
 * import ipguard from '@nascencestudio/ipguard';
 * export default defineStudioCMSConfig({ plugins: [ipguard()] });
 * ```
 */
export function ipguard(options: IpGuardOptions = {}): IpGuardPlugin {
	const runtimeConfig = checkOptions(options);
	return definePlugin({
		identifier: PACKAGE_NAME,
		name: 'IP Guard',
		hooks: {
			'studiocms:astro-config': ({ addIntegrations }) => {
				addIntegrations({
					name: PACKAGE_NAME,
					hooks: {
						'astro:config:setup': ({ injectRoute, addMiddleware, updateConfig }) => {
							injectRoute({
								pattern: ADMIN_ROUTE,
								entrypoint: resolve('./runtime/admin-endpoint.js'),
								prerender: false,
							});
							// Bans are checked before everything else (ADR 0001 §2).
							addMiddleware({ entrypoint: resolve('./runtime/middleware.js'), order: 'pre' });
							updateConfig({
								vite: {
									plugins: [
										{
											name: 'ipguard:config',
											resolveId: (id: string) => (id === CONFIG_MODULE ? `\0${CONFIG_MODULE}` : undefined),
											load: (id: string) =>
												id === `\0${CONFIG_MODULE}` ? `export default ${JSON.stringify(runtimeConfig)};` : undefined,
										},
									],
								},
							});
						},
					},
				});
			},
			'studiocms:dashboard': ({ setDashboard }) => {
				setDashboard({
					translations: { en: {} },
					dashboardPages: {
						admin: [
							{
								title: { en: 'IP Guard' },
								description: 'Blocked, flagged and trusted addresses; spam protection settings.',
								route: 'ipguard',
								icon: 'heroicons:shield-check',
								sidebar: 'double',
								requiredPermissions: 'admin',
								innerSidebarComponent: resolve('./runtime/IpGuardNav.astro'),
								pageBodyComponent: resolve('./runtime/IpGuardPage.astro'),
							},
						],
					},
				});
			},
		},
	});
}

export default ipguard;
