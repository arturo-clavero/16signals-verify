import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { rowPieces, readRow } from './row-structure.mjs';
import { fixtureText } from './row-fixture.mjs';

// What the verifier sees: revealed text, hidden kinds and lengths.
const visible = (text, pieces) => pieces.map(p => p.kind === 'R' ? { kind: 'R', text: text.slice(p.start, p.end) } : { kind: 'H', length: p.end - p.start });
const roundTrip = text => readRow(visible(text, rowPieces(text)));

test('pieces cover the row exactly and hide every sensitive value', () => {
  const text = fixtureText({ request: { name: 'demo-db', nested: [{ a: '"}' }] }, response: { uuid: 'x' } });
  const pieces = rowPieces(text);
  assert.equal(pieces[0].start, 0);
  assert.equal(pieces.at(-1).end, text.length);
  for (let i = 1; i < pieces.length; i++) assert.equal(pieces[i].start, pieces[i - 1].end);
  const revealed = pieces.filter(p => p.kind === 'R').map(p => text.slice(p.start, p.end)).join('');
  for (const secret of ['someone@example.test', '192.0.2.1', 'a'.repeat(32), 'b'.repeat(32), 'demo-db', 'wrangler', 'res-1', 'Create database', '07:00:55'])
    assert.ok(!revealed.includes(secret), secret);
  for (const shown of ['"product":"d1"', '"type":"database"', '"context":"oauth"', '"result":"success"', '"time":"2026-11-25'])
    assert.ok(revealed.includes(shown), shown);
  assert.equal(pieces.filter(p => p.kind === 'A').length, 1);
  assert.equal(pieces.filter(p => p.kind === 'T').length, 1);
  // Every V piece is one JSON value by itself.
  for (const p of pieces.filter(p => p.kind === 'V' || p.kind === 'A')) JSON.parse(text.slice(p.start, p.end));
});

test('the reader returns the public fields', () => {
  const text = fixtureText();
  assert.deepEqual(roundTrip(text), {
    product: 'd1', type: 'database', action: 'create', result: 'success', actorType: 'user', context: 'oauth', scope: 'accounts', day: '2026-11-25',
    hidden: rowPieces(text).filter(p => p.kind !== 'R').map(p => p.kind),
  });
  const queue = roundTrip(fixtureText({ product: 'queues', type: null, resourceId: null, raw: false, description: null }));
  assert.equal(queue.type, '');
  assert.equal(queue.product, 'queues');
  // Part 2 rows: a Workflow deploy (no type, like a queue) and a cron change (request is an array).
  const flow = roundTrip(fixtureText({ product: 'workflows', type: null, action: 'update', description: 'Update workflow' }));
  assert.deepEqual([flow.product, flow.type, flow.action], ['workflows', '', 'update']);
  const cron = roundTrip(fixtureText({ product: 'workers', type: 'scripts.schedules', action: 'update', request: [{ cron: '0 3 * * *' }],
    response: { schedules: [{ created_on: '2026-11-25T06:40:00.000000Z', cron: '0 3 * * *', modified_on: '2026-11-25T06:40:00.000000Z' }] } }));
  assert.deepEqual([cron.type, cron.action], ['scripts.schedules', 'update']);
  const tokens = roundTrip(fixtureText({ product: null, type: 'tokens', token: { id: 't', name: 'n' }, zone: { id: 'z', name: 'example.test' }, value: 'v' }));
  assert.equal(tokens.product, '');
  for (const time of ['2026-11-25T07:00:55Z', '2026-11-25T07:00:55.1Z', '2026-11-25T07:00:55.12Z']) assert.equal(roundTrip(fixtureText({ time })).day, '2026-11-25');
});

test('the live key sets all fit the grammar', () => {
  const shapes = JSON.parse(readFileSync(new URL('./fixtures/row-shapes.json', import.meta.url)));
  for (const [name, { shape }] of Object.entries(shapes)) {
    // Shapes carry type markers as values; any string is fine for the grammar except the revealed short fields.
    const fill = (v, path) => v && typeof v === 'object' ? Array.isArray(v) ? v.map(x => fill(x, path)) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, `${path}.${k}`)]))
      : path === '.action.time' ? '2026-11-25T07:00:55.123Z' : v;
    const text = JSON.stringify(fill(shape, ''));
    const fields = roundTrip(text);
    assert.equal(`${fields.product}/${fields.type} ${fields.action}`, name.split(' ').slice(0, 2).join(' ').replace('/undefined', '/'), name);
  }
});

test('rows outside the grammar are refused when splitting', () => {
  const bad = (text, code) => assert.throws(() => rowPieces(text), new RegExp(`CF_ROW_STRUCTURE:${code}`));
  const row = JSON.parse(fixtureText());
  bad(JSON.stringify({ ...row, extra: 1 }), 'key:extra');
  bad(JSON.stringify({ action: row.action, account: row.account, actor: row.actor, resource: row.resource }), 'order:account');
  bad(JSON.stringify({ ...row, actor: { ...row.actor, id: 5 } }), 'actor-id');
  bad(JSON.stringify({ ...row, actor: { context: 'oauth', type: 'user' } }), 'missing:id');
  bad(JSON.stringify({ ...row, action: { ...row.action, time: '2026-11-25 07:00' } }), 'time');
  bad(JSON.stringify({ ...row, action: { ...row.action, type: 'Create Database' } }), 'short:type');
  bad(fixtureText() + ' ', 'trailing');
  bad('x'.repeat(9000), 'size');
});

test('the reader refuses forged skeletons', () => {
  const text = fixtureText();
  const pieces = visible(text, rowPieces(text));
  const bad = (forged, code) => assert.throws(() => readRow(forged), new RegExp(`CF_ROW_STRUCTURE:${code}`));
  // Revealing the actor id or the time tail instead of hiding it, or hiding a revealed field.
  const at = kind => rowPieces(text).findIndex(p => p.kind === kind);
  bad(pieces.map((p, i) => i === at('A') ? { kind: 'R', text: '"x"' } : p), 'hidden:actor.id');
  bad(pieces.map((p, i) => i === at('T') ? { kind: 'R', text: 'T00:00:00Z"' } : p), 'time');
  const firstR = pieces.findIndex(p => p.kind === 'R' && p.text.includes('"product":'));
  bad(pieces.map((p, i) => i === firstR ? { kind: 'R', text: p.text.replace('"product":"d1"', '"product":') } : p), 'hidden:resource.product|short|separator');
  bad([...pieces, { kind: 'R', text: ',' }], 'trailing');
  bad(pieces.map(p => p.kind === 'R' ? { ...p, text: p.text.replace('"result":"success"', '"result":"success\n"') } : p), 'revealed');
  bad(pieces.map(p => p.kind === 'H' ? { ...p, length: 0 } : p), 'hidden-length');
  bad([{ kind: 'X' }], 'kind');
  bad([{ kind: 'V', length: 3 }], 'kind');
  bad(pieces.map(p => p.kind === 'R' ? { ...p, text: p.text.replace('"time":"2026-11-25', '"time":"2026-02-30') } : p), 'time');
});
