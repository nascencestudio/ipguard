/// <reference types="studiocms/v/types" />
/**
 * Who is making a request, via StudioCMS's own session validation (the plugin's
 * routes are outside the dashboard, where StudioCMS doesn't resolve the
 * session itself). Any failure counts as anonymous (fail closed).
 */
import { User } from 'studiocms:auth/lib';
import type { AstroGlobal } from 'astro';
import { Effect, runEffect } from 'studiocms/effect';

const RANK: Record<string, number> = { visitor: 1, editor: 2, admin: 3, owner: 4 };
const EDITOR = 2;
const ADMIN = 3;

export interface IpGuardViewer {
	isEditor: boolean;
	isAdmin: boolean;
	isLoggedIn: boolean;
	name: string | null;
}

const ANONYMOUS: IpGuardViewer = { isEditor: false, isAdmin: false, isLoggedIn: false, name: null };

export async function getIpGuardViewer(context: Pick<AstroGlobal, 'cookies'>): Promise<IpGuardViewer> {
	try {
		const data = await runEffect(
			Effect.gen(function* () {
				const user = yield* User;
				return yield* user.getUserData(context as never);
			}),
		);
		if (!data?.isLoggedIn || !data.user) return ANONYMOUS;
		const rank = RANK[data.permissionLevel] ?? 0;
		return { isEditor: rank >= EDITOR, isAdmin: rank >= ADMIN, isLoggedIn: true, name: data.user.name ?? null };
	} catch (error) {
		console.warn('[ipguard] session check failed; treating request as anonymous', error);
		return ANONYMOUS;
	}
}
