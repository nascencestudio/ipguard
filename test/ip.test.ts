import { describe, expect, it } from 'vitest';
import {
	type Cidr,
	cidrContains,
	DEFAULT_TRUSTED_PROXIES,
	formatCidr,
	formatIp,
	isPublic,
	parseCidr,
	parseIp,
	resolveClientIp,
	subjectOf,
} from '../src/ip.js';

const ip = (text: string) => {
	const parsed = parseIp(text);
	if (!parsed) throw new Error(`not an address: ${text}`);
	return parsed;
};
const canon = (text: string) => formatIp(ip(text));

describe('parsing and formatting addresses', () => {
	it('reads IPv4 strictly', () => {
		expect(canon('192.0.2.1')).toBe('192.0.2.1');
		expect(canon(' 8.8.8.8 ')).toBe('8.8.8.8');
		for (const bad of [
			'256.1.1.1',
			'1.2.3',
			'1.2.3.4.5',
			'01.2.3.4',
			'1.2.3.-4',
			'1.2.3.4x',
			'0x7f.0.0.1',
			'1e2.0.0.1',
			'1.2.3.4 5',
		]) {
			expect(parseIp(bad), bad).toBeNull();
		}
	});

	it('reads IPv6 and writes it the canonical way (RFC 5952)', () => {
		expect(canon('2001:0DB8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1');
		expect(canon('2001:db8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1');
		expect(canon('2001:db8::')).toBe('2001:db8::');
		expect(canon('::')).toBe('::');
		expect(canon('::1')).toBe('::1');
		expect(canon('2001:db8:1:1:1:1:1:1')).toBe('2001:db8:1:1:1:1:1:1');
		expect(canon('2001:db8:0:1:1:1:1:1')).toBe('2001:db8:0:1:1:1:1:1');
		expect(canon('64:ff9b::192.0.2.33')).toBe('64:ff9b::c000:221');
	});

	it('reads IPv4-mapped IPv6 as IPv4', () => {
		expect(ip('::ffff:192.0.2.1')).toEqual(ip('192.0.2.1'));
		expect(ip('::ffff:c000:201')).toEqual(ip('192.0.2.1'));
	});

	it('refuses everything else', () => {
		for (const bad of [
			'',
			'abc',
			'1::2::3',
			'1:2:3:4:5:6:7:8:9',
			'1:2:3:4:5:6:7',
			'12345::',
			'fe80::1%eth0',
			'[::1]',
			'::1/128',
			'1.2.3.4/32',
			'g::1',
			'1:2:3:4:5:6:7::8',
			'::ffff:1.2.3',
			'2001:db8::1'.repeat(10),
			42,
			null,
		]) {
			expect(parseIp(bad), String(bad)).toBeNull();
		}
	});
});

describe('ranges', () => {
	it('reads ranges and single addresses, clearing host bits', () => {
		expect(formatCidr(parseCidr('10.1.2.3/8') as Cidr)).toBe('10.0.0.0/8');
		expect(formatCidr(parseCidr('192.0.2.7') as Cidr)).toBe('192.0.2.7');
		expect(formatCidr(parseCidr('192.0.2.7/32') as Cidr)).toBe('192.0.2.7');
		expect(formatCidr(parseCidr('2001:db8:aa:bb:1:2:3:4/64') as Cidr)).toBe('2001:db8:aa:bb::/64');
		expect(formatCidr(parseCidr('0.0.0.0/0') as Cidr)).toBe('0.0.0.0/0');
		expect(formatCidr(parseCidr('::ffff:192.0.2.0/120') as Cidr)).toBe('192.0.2.0/24');
		for (const bad of ['10.0.0.0/33', '::/129', '10.0.0.0/', '10.0.0.0/08', '10.0.0.0/-1', 'x/8', '10.0.0.0/8/8']) {
			expect(parseCidr(bad), bad).toBeNull();
		}
	});

	it('matches addresses of the same version only', () => {
		const net = parseCidr('192.0.2.0/24') as Cidr;
		expect(cidrContains(net, ip('192.0.2.255'))).toBe(true);
		expect(cidrContains(net, ip('192.0.3.0'))).toBe(false);
		expect(cidrContains(net, ip('::ffff:192.0.2.9'))).toBe(true);
		expect(cidrContains(parseCidr('::/0') as Cidr, ip('192.0.2.1'))).toBe(false);
		expect(cidrContains(parseCidr('2001:db8::/32') as Cidr, ip('2001:db8:ffff::1'))).toBe(true);
	});

	it('groups an IPv6 visitor by its /64, IPv4 by the address', () => {
		expect(formatCidr(subjectOf(ip('2001:db8:1:2:aaaa:bbbb:cccc:dddd')))).toBe('2001:db8:1:2::/64');
		expect(subjectOf(ip('2001:db8:1:2::1'))).toEqual(subjectOf(ip('2001:db8:1:2:ffff::9')));
		expect(formatCidr(subjectOf(ip('198.51.100.20')))).toBe('198.51.100.20');
	});
});

describe('public addresses', () => {
	it('knows private, reserved and documentation ranges', () => {
		for (const pub of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2a01:4f8::1'])
			expect(isPublic(ip(pub)), pub).toBe(true);
		for (const priv of [
			'10.1.2.3',
			'172.16.0.1',
			'172.31.255.255',
			'192.168.1.1',
			'127.0.0.1',
			'169.254.1.1',
			'100.64.0.1',
			'192.0.2.1',
			'198.51.100.1',
			'203.0.113.9',
			'224.0.0.1',
			'255.255.255.255',
			'0.0.0.0',
			'::1',
			'::',
			'fe80::1',
			'fd00::1',
			'ff02::1',
			'2001:db8::1',
		]) {
			expect(isPublic(ip(priv)), priv).toBe(false);
		}
		expect(isPublic(ip('172.32.0.1'))).toBe(true);
	});
});

describe('the visitor’s real address', () => {
	const trusted = DEFAULT_TRUSTED_PROXIES.map((c) => parseCidr(c) as Cidr);
	const resolve = (remote: string, xff?: string) => {
		const found = resolveClientIp(remote, xff, trusted);
		return found ? formatIp(found) : null;
	};

	it('uses the connecting address when it isn’t a trusted proxy (a forged header is ignored)', () => {
		expect(resolve('8.8.8.8', '1.2.3.4')).toBe('8.8.8.8');
	});

	it('behind a trusted proxy, takes the rightmost untrusted address', () => {
		expect(resolve('172.18.0.2', '8.8.8.8')).toBe('8.8.8.8');
		// The visitor sent "1.2.3.4" themselves; the proxy appended their real address.
		expect(resolve('172.18.0.2', '1.2.3.4, 8.8.4.4')).toBe('8.8.4.4');
		expect(resolve('127.0.0.1', '8.8.8.8, 10.0.0.5')).toBe('8.8.8.8');
		expect(resolve('::1', ' 2001:db8::7 ')).toBe('2001:db8::7');
	});

	it('skips garbage and falls back sensibly', () => {
		expect(resolve('127.0.0.1', 'nonsense, 8.8.8.8')).toBe('8.8.8.8');
		expect(resolve('127.0.0.1', '')).toBe('127.0.0.1');
		expect(resolve('127.0.0.1', '10.0.0.1, 10.0.0.2')).toBe('10.0.0.1');
		expect(resolve('not an ip', '8.8.8.8')).toBeNull();
	});
});
