import assert from 'node:assert/strict';
import test from 'node:test';
import { planCloudflareSession, planView, inspectCloudflareSession, cloudflarePageRows } from './session.mjs';
import { requestBytes, responseBytes, identityBody, pageBody, FIXTURE_TOKEN } from './session-fixture.mjs';
import { FIXTURE_USER, FIXTURE_ACCOUNT } from './row-fixture.mjs';

const dec = b => new TextDecoder().decode(b);
const revealed = view => dec(view.bytes);

test('identity session: only the id is hidden in the body prefix; the token never shows', () => {
  const sent = requestBytes('identity'), recv = responseBytes(identityBody());
  const plan = planCloudflareSession('identity', sent, recv);
  const view = planView(sent, recv, plan);
  const out = inspectCloudflareSession(view, 'identity');
  assert.equal(out.identity.length, 34);
  assert.ok(!revealed(view.sent).includes(FIXTURE_TOKEN));
  assert.ok(!revealed(view.recv).includes(FIXTURE_USER));
  assert.ok(!revealed(view.recv).includes('someone@example.test'));
  assert.ok(!revealed(view.recv).includes('__cfruid'));
  assert.equal(out.obligations.filter(o => o.need === 'value').length, 1);
  assert.ok(out.obligations.filter(o => o.need === 'header').length >= 2);
});

test('page session: selected rows give public fields, every hidden piece an obligation', () => {
  const rows = [{}, { product: 'queues', type: null, action: 'create' }, { product: 'workers', type: 'scripts', action: 'update', request: { a: [1, '"}'] } }];
  const sent = requestBytes('page'), body = pageBody(rows);
  const starts = cloudflarePageRows(body).map(r => r.start);
  const recv = responseBytes(body, [starts[1] - 1, starts[2] - starts[1]]);
  const plan = planCloudflareSession('P0', sent, recv, [0, 2]);
  const view = planView(sent, recv, plan);
  const out = inspectCloudflareSession(view, 'P0');
  assert.deepEqual(out.rows.map(r => `${r.product}/${r.type} ${r.action} ${r.context} ${r.day}`), ['d1/database create oauth 2026-11-25', 'workers/scripts update oauth 2026-11-25']);
  const text = revealed(view.recv) + revealed(view.sent);
  for (const secret of [FIXTURE_TOKEN, FIXTURE_ACCOUNT, FIXTURE_USER, 'someone@example.test', '192.0.2.1', '07:00:55']) assert.ok(!text.includes(secret), secret);
  assert.ok(!text.includes('"product":"queues"'), 'unselected rows stay gaps');
  const needs = out.obligations.reduce((m, o) => ({ ...m, [o.need]: (m[o.need] ?? 0) + 1 }), {});
  assert.equal(needs.actor, 2);
  assert.equal(needs.tail, 2);
  assert.equal(needs.value, 15); // 7 per fixture row + the request object
});

test('a row crossing a chunk boundary is refused by the planner', () => {
  const body = pageBody([{}, {}]), at = body.indexOf('"actor"') + 3;
  assert.throws(() => planCloudflareSession('P0', requestBytes('page'), responseBytes(body, [at]), [0]), /crosses-chunk|row:0/);
  assert.ok(planCloudflareSession('P0', requestBytes('page'), responseBytes(body, [at]), [1]));
});

test('forged views are refused', () => {
  const body = pageBody([{}, {}]);
  const sent = requestBytes('page'), recv = responseBytes(body, [cloudflarePageRows(body)[1].start]);
  const plan = planCloudflareSession('P0', sent, recv, [0, 1]);
  const bad = (mutate, code) => {
    const forged = structuredClone(plan); mutate(forged);
    assert.throws(() => inspectCloudflareSession(planView(sent, recv, forged), 'P0'), new RegExp(`CF_(SESSION_INVALID|ROW_STRUCTURE):${code}`));
  };
  const reveal = r => { r.handler.action = { kind: 'REVEAL' }; };
  // The token revealed.
  bad(p => reveal(p.sentRangesWithHandlers.find(r => r.handler.action.kind === 'HASH' && r.handler.part === 'HEADERS')), 'public-header:authorization');
  // The account id revealed.
  bad(p => reveal(p.sentRangesWithHandlers.find(r => r.handler.action.kind === 'HASH')), 'request-line');
  // A gap in the request.
  bad(p => { p.sentRangesWithHandlers.splice(1, 1); }, 'sent-gap');
  // A chunk-size line hidden.
  bad(p => { const r = p.recvRangesWithHandlers.find(r => r.handler.part === 'BODY'); r.handler.action = { kind: 'HASH', algorithm: 'SHA256' }; }, '');
  // The actor id revealed.
  bad(p => { const hashes = p.recvRangesWithHandlers.filter(r => r.handler.action.kind === 'HASH' && r.handler.part === 'BODY'); reveal(hashes[2]); }, '');
  // The status line hidden.
  bad(p => { p.recvRangesWithHandlers[0].handler.action = { kind: 'HASH', algorithm: 'SHA256' }; }, 'not-public');
});
