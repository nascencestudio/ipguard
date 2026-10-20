// Copies non-TypeScript sources (Astro components, CSS, ambient declarations) into
// dist/, since tsc only emits .js/.d.ts for .ts files.
import { cpSync, globSync } from 'node:fs';
import { join } from 'node:path';

const pkg = join(import.meta.dirname, '..');

for (const file of globSync(['src/**/*.astro', 'src/**/*.d.ts', 'src/**/*.css', 'src/thumbnails/*.svg'], {
	cwd: pkg,
})) {
	cpSync(join(pkg, file), join(pkg, file.replace(/^src/, 'dist')));
}
