import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverCloudflare, selectCloudflareWindows, selectCloudflareRows, provableRow, CF_DISCOVERY } from './discovery.mjs';
import { fixtureRow, FIXTURE_USER, FIXTURE_ACCOUNT } from './row-fixture.mjs';

const now = Date.parse('2026-11-25T08:00:00Z'), token = 't'.repeat(40);
const at = (daysAgo, minute = 0) => new Date(now - daysAgo * 864e5 - minute * 60000).toISOString();

test('discovery follows the cursor, stops on budget, and degrades after the first read', async () => {
  const calls = [];
  const read = async req => { calls.push(new URL(req.url).searchParams.get('cursor')); return { success: true, result: [fixtureRow()], result_info: { cursor: `c${calls.length}` } }; };
  const rows = await discoverCloudflare({ read, token, userId: FIXTURE_USER, accountId: FIXTURE_ACCOUNT, now });
  assert.equal(rows.length, CF_DISCOVERY.reads);
  assert.deepEqual(calls, [null, 'c1', 'c2', 'c3', 'c4']);
  let n = 0;
  const flaky = async () => { if (n++) throw new Error('net'); return { success: true, result: [fixtureRow()], result_info: { cursor: 'x' } }; };
  assert.equal((await discoverCloudflare({ read: flaky, token, userId: FIXTURE_USER, accountId: FIXTURE_ACCOUNT, now })).length, 1);
  await assert.rejects(discoverCloudflare({ read: async () => { throw new Error('401'); }, token, userId: FIXTURE_USER, accountId: FIXTURE_ACCOUNT, now }), /CF_DISCOVERY_FAILED/);
  await assert.rejects(discoverCloudflare({ read: async () => ({ success: false }), token, userId: FIXTURE_USER, accountId: FIXTURE_ACCOUNT, now }), /CF_DISCOVERY_FAILED/);
});

test('provable rows: own catalog evidence inside the window', () => {
  assert.equal(provableRow(fixtureRow({ time: at(1) }), FIXTURE_USER, now), true);
  assert.equal(provableRow(fixtureRow({ time: at(91) }), FIXTURE_USER, now), false);
  assert.equal(provableRow(fixtureRow({ time: at(1), actorId: 'f'.repeat(32) }), FIXTURE_USER, now), false);
  assert.equal(provableRow(fixtureRow({ time: at(1), product: 'dns', type: 'record' }), FIXTURE_USER, now), false);
  assert.equal(provableRow(fixtureRow({ time: at(1), response: { big: 'x'.repeat(5000) } }), FIXTURE_USER, now), false);
});

test('windows: disjoint blocks of CF_PAGE_LIMIT_MAX rows, most new (group, day) pairs first, bounds around the rows', () => {
  // 4 blocks of 12: all d1 on one day, then two blocks spread over products and days, then 6 workers rows.
  const rows = [
    ...Array.from({ length: 12 }, (_, i) => fixtureRow({ time: at(1, i) })),
    ...Array.from({ length: 24 }, (_, i) => fixtureRow({ time: at(2 + i, 0), ...[{}, { product: 'queues', type: null }, { product: 'vectorize', type: 'indexes' }][i % 3] })),
    ...Array.from({ length: 6 }, (_, i) => fixtureRow({ time: at(40, i), product: 'workers', type: 'scripts', action: 'update' })),
  ];
  const windows = selectCloudflareWindows(rows, FIXTURE_USER, now);
  assert.equal(windows.length, 3);
  for (const w of windows) assert.ok(Date.parse(w.since) < Date.parse(w.before) && w.limit === 12);
  for (let i = 1; i < windows.length; i++) assert.ok(Date.parse(windows[i].before) <= Date.parse(windows[i - 1].since) + 2);
  const inside = w => rows.filter(r => Date.parse(r.action.time) > Date.parse(w.since) && Date.parse(r.action.time) < Date.parse(w.before)).length;
  // The two spread blocks first; the one-day d1 and workers blocks tie (one new pair each): the newer one wins.
  assert.deepEqual(windows.map(inside), [12, 12, 12]);
  // A single row gives a window of 2 ms around it (never since == before).
  const one = selectCloudflareWindows([fixtureRow({ time: at(3) })], FIXTURE_USER, now);
  assert.equal(Date.parse(one[0].before) - Date.parse(one[0].since), 2);
  assert.deepEqual(selectCloudflareWindows([], FIXTURE_USER, now), []);
});

test('rows inside a page: mappable provable rows, new pairs first, capped', () => {
  const rows = Array.from({ length: 25 }, (_, i) => fixtureRow({ time: at(1, i), ...(i === 7 ? { product: 'queues', type: null } : {}) }));
  const picked = selectCloudflareRows(rows, i => i !== 24, FIXTURE_USER, now);
  assert.equal(picked.length, 12);
  assert.ok(!picked.includes(24) && picked.includes(7));
  // Rows before the last pick are covered, so a row that cannot be hidden (here: not inside one chunk) ends the picks.
  assert.deepEqual(selectCloudflareRows(rows, i => i !== 0, FIXTURE_USER, now), []);
  assert.deepEqual(selectCloudflareRows(rows, i => i !== 3, FIXTURE_USER, now), [0, 1, 2]);
  assert.deepEqual(selectCloudflareRows([fixtureRow({ time: at(1), actorType: 'system' })], () => true, FIXTURE_USER, now), []);
});
