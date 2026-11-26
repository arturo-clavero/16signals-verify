// Synthetic Audit Logs v2 rows with the live key sets (fixtures/row-shapes.json) and fake values. Never real data.
// Pass null to leave an optional key out.
export const FIXTURE_USER = 'a'.repeat(32);
export const FIXTURE_ACCOUNT = 'b'.repeat(32);

export function fixtureRow({ product = 'd1', type = 'database', action = 'create', result = 'success', context = 'oauth',
  actorType = 'user', actorId = FIXTURE_USER, time = '2026-11-25T07:00:55.123Z', request, response, value, raw = true, zone, token,
  resourceId = 'res-1', description = 'Create database' } = {}) {
  const row = {
    account: { id: FIXTURE_ACCOUNT, name: 'Example "quoted" account' },
    action: { ...(description === null ? {} : { description }), result, time, type: action },
    actor: { context, email: 'someone@example.test', id: actorId, ip_address: '192.0.2.1', ...(token ? { token } : {}), type: actorType },
    id: '00000000-0000-4000-8000-000000000001',
    ...(raw ? { raw: { cf_ray_id: '0123456789abcdef', method: 'POST', status_code: 200, uri: '/accounts/x/d1/database', user_agent: 'wrangler/4.168.0' } } : {}),
    resource: {
      ...(resourceId === null ? {} : { id: resourceId }), ...(product === null ? {} : { product }),
      ...(request === undefined ? {} : { request }), ...(response === undefined ? {} : { response }), scope: 'accounts',
      ...(type === null ? {} : { type }), ...(value === undefined ? {} : { value }),
    },
    ...(zone ? { zone } : {}),
  };
  return row;
}

export const fixtureText = options => JSON.stringify(fixtureRow(options));
