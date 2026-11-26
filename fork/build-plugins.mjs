// Bundle the extension's built-in plugins from source:
//   node fork/build-plugins.mjs [out dir]     # default fork/out/plugins
// Builds private-proof/<provider>/plugin.ts into <out dir>/<id>.js, one ES module per plugin with
// `export default { main, run, config }` (what the extension's evaluator reads). build.sh uses that directory as
// FORK_PLUGIN_DIR when none is given.
//
// Deterministic: the exact esbuild version is pinned in the root package.json, and a minified bundle has no paths,
// comments or timestamps, so the same sources give the same bytes (and sha256, the plugin's fingerprint) everywhere.
// The run values stay placeholders the extension fills in: `'__PLUGIN_PARAMS__'` and, per method,
// `"__VERIFIER_URL_<METHOD>__"` / `"__PROXY_URL_<METHOD>__"`, each a whole string literal.
import { createHash } from 'node:crypto';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const ESBUILD_VERSION = '0.27.7';

/** id -> { source, method } of every plugin built here (GCP's plugin is not in this repository). */
export const PLUGINS = Object.freeze({
  'aws-private-work': { source: 'private-proof/aws/plugin.ts', method: 'AWS_ACCOUNT' },
  'cloudflare-private-work': { source: 'private-proof/cloudflare/plugin.ts', method: 'CLOUDFLARE_ACCOUNT' },
});

export const PLUGIN_SIZE_LIMIT = 200 * 1024;
const urlPlaceholders = method => [`__VERIFIER_URL_${method}__`, `__PROXY_URL_${method}__`];

/** Problems of one built bundle (empty = fine). */
export function bundleProblems(code, method) {
  const problems = [];
  if (Buffer.byteLength(code, 'utf8') >= PLUGIN_SIZE_LIMIT) problems.push(`bundle is not under ${PLUGIN_SIZE_LIMIT} bytes`);
  for (const token of urlPlaceholders(method)) {
    let at = code.indexOf(token);
    if (at < 0) problems.push(`placeholder ${token} missing`);
    for (; at >= 0; at = code.indexOf(token, at + token.length)) {
      if (code[at - 1] !== '"' || code[at + token.length] !== '"') { problems.push(`placeholder ${token} is not a whole "…" string literal`); break; }
    }
  }
  if (!/(["'])__PLUGIN_PARAMS__\1/.test(code)) problems.push('placeholder __PLUGIN_PARAMS__ missing or not a whole string literal');
  // Plugins pass REVEAL handlers only; a HASH commitment costs the prover far more memory.
  if (/(["'`])HASH\1/.test(code)) problems.push('declares a HASH handler action');
  if (!/export\s*\{[^}]*\bas default\b|export\s+default\b/.test(code)) problems.push('no default export');
  return problems;
}

/** Build every plugin into `outDir`; returns { id: sha256 }. */
export async function buildPlugins(outDir = join(ROOT, 'fork/out/plugins')) {
  const { build, version } = await import('esbuild');
  if (version !== ESBUILD_VERSION) throw new Error(`esbuild ${version} installed, the plugins are built with ${ESBUILD_VERSION} (npm ci)`);
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });
  const fingerprints = {};
  for (const [id, { source, method }] of Object.entries(PLUGINS)) {
    const outfile = join(outDir, `${id}.js`);
    await build({
      entryPoints: [join(ROOT, source)],
      bundle: true,
      format: 'esm',
      target: 'es2020',
      platform: 'neutral',
      minify: true,
      legalComments: 'none',
      logLevel: 'warning',
      define: Object.fromEntries(urlPlaceholders(method).map(p => [p, JSON.stringify(p)])),
      outfile,
    });
    const bytes = await readFile(outfile);
    const problems = bundleProblems(bytes.toString('utf8'), method);
    if (problems.length) throw new Error(`${id}: ${problems.join('; ')}`);
    fingerprints[id] = createHash('sha256').update(bytes).digest('hex');
  }
  return fingerprints;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outDir = resolve(process.argv[2] || join(ROOT, 'fork/out/plugins'));
  buildPlugins(outDir).then(fingerprints => {
    for (const [id, sha256] of Object.entries(fingerprints)) console.log(`built plugin ${id}.js (sha256 ${sha256})`);
  }, error => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
