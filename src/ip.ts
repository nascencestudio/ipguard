/**
 * IP addresses and ranges (ADR 0001): strict parsing of IPv4 and IPv6 (no zone ids, no leading zeros in
 * IPv4 octets, which some parsers read as octal), canonical formatting (RFC 5952 for IPv6), CIDR ranges,
 * the "subject" an automatic action applies to (an IPv4 address, or an IPv6 /64, since one IPv6 visitor
 * can rotate through a whole /64), whether an address is public, and the visitor's real address behind
 * trusted proxies. Pure.
 */

export type IpVersion = 4 | 6;

export interface Ip {
	version: IpVersion;
	/** The address as a number (32 or 128 bits). */
	value: bigint;
}

export interface Cidr {
	version: IpVersion;
	/** The network address (host bits cleared). */
	network: bigint;
	prefix: number;
}

const BITS: Record<IpVersion, number> = { 4: 32, 6: 128 };
const MAX_INPUT = 64;

function parseV4(text: string): bigint | null {
	const parts = text.split('.');
	if (parts.length !== 4) return null;
	let value = 0n;
	for (const part of parts) {
		if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
		const n = Number(part);
		if (n > 255) return null;
		value = (value << 8n) | BigInt(n);
	}
	return value;
}

function parseV6(text: string): bigint | null {
	if (!/^[0-9a-fA-F:.]+$/.test(text)) return null;
	// An embedded IPv4 address in the last 32 bits (e.g. ::ffff:192.0.2.1).
	let tail: bigint | null = null;
	let body = text;
	const lastColon = text.lastIndexOf(':');
	if (text.includes('.')) {
		tail = parseV4(text.slice(lastColon + 1));
		if (tail === null) return null;
		body = `${text.slice(0, lastColon + 1)}0:0`;
	}
	const halves = body.split('::');
	if (halves.length > 2) return null;
	const groups = (half: string) => (half === '' ? [] : half.split(':'));
	const head = groups(halves[0] ?? '');
	const rest = halves.length === 2 ? groups(halves[1] ?? '') : [];
	const total = head.length + rest.length;
	if (halves.length === 1 ? total !== 8 : total > 7) return null;
	const all = [...head, ...Array(8 - total).fill('0'), ...rest];
	let value = 0n;
	for (const group of all) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
		value = (value << 16n) | BigInt(Number.parseInt(group, 16));
	}
	if (tail !== null) value = (value & ~0xffffffffn) | tail;
	return value;
}

const V4_MAPPED = 0xffff00000000n;

/** An address, or null when it isn't a valid one. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is read as IPv4. */
export function parseIp(input: unknown): Ip | null {
	if (typeof input !== 'string') return null;
	const text = input.trim();
	if (text === '' || text.length > MAX_INPUT) return null;
	if (!text.includes(':')) {
		const v4 = parseV4(text);
		return v4 === null ? null : { version: 4, value: v4 };
	}
	const v6 = parseV6(text);
	if (v6 === null) return null;
	if (v6 >> 32n === V4_MAPPED >> 32n) return { version: 4, value: v6 & 0xffffffffn };
	return { version: 6, value: v6 };
}

/** The canonical text of an address (IPv6 per RFC 5952: lowercase, zeros compressed once). */
export function formatIp(ip: Ip): string {
	if (ip.version === 4) {
		return [24n, 16n, 8n, 0n].map((shift) => String((ip.value >> shift) & 0xffn)).join('.');
	}
	const groups = Array.from({ length: 8 }, (_, i) => Number((ip.value >> BigInt((7 - i) * 16)) & 0xffffn));
	// The longest run of two or more zero groups (the first one on a tie) becomes "::".
	let bestStart = -1;
	let bestLength = 1;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j++;
		if (j - i > bestLength) {
			bestStart = i;
			bestLength = j - i;
		}
		i = j;
	}
	const hex = groups.map((g) => g.toString(16));
	if (bestStart < 0) return hex.join(':');
	const left = hex.slice(0, bestStart).join(':');
	const right = hex.slice(bestStart + bestLength).join(':');
	return `${left}::${right}`;
}

const mask = (version: IpVersion, prefix: number) => {
	const bits = BITS[version];
	return prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
};

/**
 * A range from `a.b.c.d/n`, `x::/n`, or a single address (a /32 or /128). Host bits are cleared
 * (`10.1.2.3/8` is `10.0.0.0/8`). Null when invalid.
 */
export function parseCidr(input: unknown): Cidr | null {
	if (typeof input !== 'string') return null;
	const text = input.trim();
	const slash = text.indexOf('/');
	const ip = parseIp(slash < 0 ? text : text.slice(0, slash));
	if (!ip) return null;
	let prefix = BITS[ip.version];
	if (slash >= 0) {
		const raw = text.slice(slash + 1);
		if (!/^(0|[1-9][0-9]{0,2})$/.test(raw)) return null;
		prefix = Number(raw);
		// An IPv4-mapped address written with an IPv6 prefix: take the IPv4 part of the prefix.
		if (ip.version === 4 && text.slice(0, slash).includes(':')) prefix -= 96;
		if (prefix < 0 || prefix > BITS[ip.version]) return null;
	}
	return { version: ip.version, network: ip.value & mask(ip.version, prefix), prefix };
}

export function formatCidr(cidr: Cidr): string {
	const address = formatIp({ version: cidr.version, value: cidr.network });
	return cidr.prefix === BITS[cidr.version] ? address : `${address}/${cidr.prefix}`;
}

export function cidrContains(cidr: Cidr, ip: Ip): boolean {
	return cidr.version === ip.version && (ip.value & mask(ip.version, cidr.prefix)) === cidr.network;
}

/** How many addresses a range covers, as a readable size (`1`, `256`, `/64`). */
export const isSingleAddress = (cidr: Cidr) => cidr.prefix === BITS[cidr.version];

/**
 * What automatic actions (rate limit, flag, blacklist, ban) apply to: the IPv4 address itself, or the
 * IPv6 address's /64.
 */
export function subjectOf(ip: Ip): Cidr {
	const prefix = ip.version === 4 ? 32 : 64;
	return { version: ip.version, network: ip.value & mask(ip.version, prefix), prefix };
}

/** Ranges that are never "public" (private, loopback, link-local, documentation, multicast, reserved). */
const NOT_PUBLIC = [
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.0.0.0/24',
	'192.0.2.0/24',
	'192.168.0.0/16',
	'198.18.0.0/15',
	'198.51.100.0/24',
	'203.0.113.0/24',
	'224.0.0.0/3',
	'2001::/23',
	'2001:db8::/32',
]
	.map(parseCidr)
	.filter((c): c is Cidr => c !== null);
const GLOBAL_V6 = parseCidr('2000::/3') as Cidr;

/** Whether an address is on the public internet (AbuseIPDB only knows about those). */
export function isPublic(ip: Ip): boolean {
	if (ip.version === 6 && !cidrContains(GLOBAL_V6, ip)) return false;
	return !NOT_PUBLIC.some((range) => cidrContains(range, ip));
}

/** Ranges trusted as proxies by default: loopback and private networks (where a reverse proxy runs). */
export const DEFAULT_TRUSTED_PROXIES = [
	'127.0.0.0/8',
	'::1/128',
	'10.0.0.0/8',
	'172.16.0.0/12',
	'192.168.0.0/16',
	'fc00::/7',
];

/**
 * The visitor's address: the connecting address, unless it's a trusted proxy; then the rightmost
 * address in `X-Forwarded-For` that isn't a trusted proxy (addresses further left can be forged by the
 * visitor). Null when nothing valid is found.
 */
export function resolveClientIp(
	remote: string | null | undefined,
	forwardedFor: string | null | undefined,
	trusted: readonly Cidr[],
): Ip | null {
	const connecting = parseIp(remote ?? '');
	const isTrusted = (ip: Ip) => trusted.some((range) => cidrContains(range, ip));
	if (!connecting || !isTrusted(connecting)) return connecting;
	const chain = (forwardedFor ?? '')
		.split(',')
		.slice(-20)
		.map((part) => parseIp(part))
		.filter((ip): ip is Ip => ip !== null);
	for (let i = chain.length - 1; i >= 0; i--) {
		const hop = chain[i] as Ip;
		if (!isTrusted(hop)) return hop;
	}
	return chain[0] ?? connecting;
}
