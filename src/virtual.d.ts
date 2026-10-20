// IP Guard's build-time configuration (written by the plugin from its options).
declare module 'virtual:ipguard/config' {
	const config: {
		/** Proxies whose X-Forwarded-For is believed (CIDR ranges). */
		trustedProxies: string[];
		/** The AbuseIPDB check endpoint (tests point it at a local fake). */
		abuseIpDbEndpoint: string;
		/** The dashboard page (after the dashboard's base path). */
		dashboardPage: string;
	};
	export default config;
}
