/**
 * Catalog v1: the Cloudflare skill groups and the Audit Logs v2 actions that count as evidence for each.
 * Activity evidence only: neither configuration correctness nor downstream outcomes.
 *
 * A Cloudflare audit row (GET /accounts/{id}/logs/audit) names what changed with resource.product, resource.type
 * (absent on some products, e.g. queues) and action.type (create / update / delete / view). Every entry below was
 * seen in a live row from the demo account (2026-11-25, see README.md); add entries only from a live sample.
 *
 * Exports:
 *   CLOUDFLARE_SKILL_AREAS  [{ id, label }]: the job-match roll-up.
 *   CLOUDFLARE_SKILL_GROUPS [{ id, label, area, jobTags }], in display order. A job tag names one group only.
 *   CLOUDFLARE_CATALOG_OPERATIONS one frozen entry per (product, type, action):
 *     product, type, action  as the row records them; `type` is '' when the row has no resource.type.
 *     group                  a CLOUDFLARE_SKILL_GROUPS id.
 *     tier                   'basic' (creates or toggles one resource), 'intermediate' (configuration whose effect
 *                            has to be understood) or 'advanced' (cross-resource or security-critical design).
 *     auto                   true when the action is usually a side effect of routine runs rather than a choice.
 *   cloudflareCatalogOperation(product, type, action)  the matching entry or undefined.
 *   countsAsEvidence(row)   true for the candidate's own successful non-view action listed in the catalog.
 *
 * The tool (Wrangler/CLI, dashboard, API token, Global API key) comes from actor.context, not from this catalog.
 */
export const CLOUDFLARE_OPERATION_TIERS = Object.freeze(['basic', 'intermediate', 'advanced']);
export const CLOUDFLARE_TOOL_CONTEXTS = Object.freeze({ oauth: 'cli', dash: 'console', api_token: 'api', api_key: 'api' });
const B = 'basic', I = 'intermediate', A = 'advanced', AUTO = true;

export const CLOUDFLARE_SKILL_AREAS = deepFreeze([
  { id: 'edge-compute', label: 'Edge compute' },
  { id: 'data-storage', label: 'Data and storage' },
  { id: 'messaging', label: 'Messaging and workflows' },
  { id: 'ai', label: 'AI and vectors' },
  { id: 'security-access', label: 'Security and access' },
]);

// [id, label, area, jobTags, operations: [product, type, action, tier, auto?]]
const groups = [
  ['workers-deploy', 'Workers deploys and versions', 'edge-compute',
    ['cloudflare-workers', 'workers', 'edge-computing', 'serverless-edge', 'wrangler'], [
      ['workers', 'scripts', 'update', B], ['workers', 'scripts.deployments', 'create', I],
      ['workers', 'scripts.versions', 'create', I]]],
  ['workers-config', 'Worker settings and routing', 'edge-compute', ['workers-routes', 'workers-dev', 'cron-triggers'], [
    ['workers', 'scripts.script-settings', 'update', I], ['workers', 'scripts.subdomain', 'create', B],
    ['workers', 'subdomain', 'update', B], ['workers', 'scripts.schedules', 'update', B]]],
  ['kv', 'Workers KV', 'data-storage', ['cloudflare-kv', 'workers-kv', 'key-value-store'], [
    ['storage', 'kv.namespaces', 'create', B], ['storage', 'kv.namespaces.values', 'update', B, AUTO]]],
  ['d1', 'D1 SQL databases', 'data-storage', ['cloudflare-d1', 'd1', 'sqlite'], [
    ['d1', 'database', 'create', B], ['d1', 'database.query', 'create', I]]],
  ['queues', 'Queues', 'messaging', ['cloudflare-queues', 'message-queues', 'messaging'], [
    ['queues', '', 'create', B], ['queues', 'consumers', 'create', I]]],
  ['workflows', 'Workflows', 'messaging', ['cloudflare-workflows', 'workflow-orchestration'], [
    ['workflows', '', 'update', I]]],
  ['vectorize', 'Vectorize indexes', 'ai', ['cloudflare-vectorize', 'vectorize', 'vector-database', 'embeddings'], [
    ['vectorize', 'indexes', 'create', I]]],
  ['secrets', 'Secrets', 'security-access', ['cloudflare-secrets-store', 'secrets-management', 'secrets'], [
    ['workers', 'scripts.secrets', 'update', B], ['secrets_store', 'stores.secrets', 'create', I]]],
  ['api-access', 'API tokens and OAuth apps', 'security-access', ['cloudflare-api', 'api-tokens', 'oauth'], [
    ['', 'tokens', 'create', I], ['', 'tokens', 'delete', B], ['oauth_clients', '', 'create', A]]],
];

function deepFreeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); }
  return value;
}

export const CLOUDFLARE_SKILL_GROUPS = deepFreeze(groups.map(([id, label, area, jobTags]) => ({ id, label, area, jobTags })));
export const CLOUDFLARE_CATALOG_OPERATIONS = deepFreeze(groups.flatMap(([group, , , , ops]) =>
  ops.map(([product, type, action, tier, auto = false]) => ({ product, type, action, group, tier, auto }))));

/** Throws unless the areas, groups and operations follow the rules above; run on the catalog when this module loads. */
export function assertCloudflareSkillCatalog(areas, skillGroups, operations) {
  const fail = what => { throw new Error(`CLOUDFLARE_SKILL_CATALOG_INVALID:${what}`); };
  const slug = /^[a-z0-9]+(-[a-z0-9]+)*$/, name = /^([a-z0-9_-]+(\.[a-z0-9_-]+)*)?$/;
  const ids = new Set(), tags = new Set(), keys = new Set();
  for (const g of skillGroups) {
    if (!slug.test(g?.id) || ids.has(g.id) || typeof g.label !== 'string' || !g.label ||
        !areas.some(a => a.id === g.area) || !Array.isArray(g.jobTags) || !g.jobTags.length) fail(g?.id);
    for (const tag of g.jobTags) { if (!slug.test(tag) || tags.has(tag)) fail(`${g.id}:${tag}`); tags.add(tag); }
    ids.add(g.id);
  }
  for (const op of operations) {
    const key = `${op?.product}/${op?.type} ${op?.action}`;
    if (!name.test(op?.product) || !name.test(op.type) || (!op.product && !op.type) ||
        !['create', 'update', 'delete'].includes(op.action) || keys.has(key) || !ids.has(op.group) ||
        !CLOUDFLARE_OPERATION_TIERS.includes(op.tier) || typeof op.auto !== 'boolean') fail(key);
    keys.add(key);
  }
  for (const id of ids) if (!operations.some(op => op.group === id)) fail(`${id}:empty`);
  for (const area of areas) if (!skillGroups.some(g => g.area === area.id)) fail(`${area.id}:no-group`);
}

assertCloudflareSkillCatalog(CLOUDFLARE_SKILL_AREAS, CLOUDFLARE_SKILL_GROUPS, CLOUDFLARE_CATALOG_OPERATIONS);

export function cloudflareCatalogOperation(product, type, action) {
  return CLOUDFLARE_CATALOG_OPERATIONS.find(op => op.product === (product ?? '') && op.type === (type ?? '') && op.action === action);
}

/** The row is the candidate's own successful change to a catalog resource (system / account actors never count). */
export function countsAsEvidence(row, userId) {
  return row?.actor?.type === 'user' && row.actor.id === userId && row.action?.result === 'success' &&
    Object.hasOwn(CLOUDFLARE_TOOL_CONTEXTS, row.actor.context) &&
    !!cloudflareCatalogOperation(row.resource?.product, row.resource?.type, row.action?.type);
}
