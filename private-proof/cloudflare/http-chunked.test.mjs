import assert from 'node:assert/strict';
import test from 'node:test';
import { parseHttpResponse, transcriptRange } from './http-chunked.mjs';

const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);
const head = extra => `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n${extra}\r\n`;
const chunked = (...parts) => head('Transfer-Encoding: chunked\r\n') +
  parts.map(p => `${enc(p).length.toString(16)}\r\n${p}\r\n`).join('') + '0\r\n\r\n';

test('chunked: decodes the body and maps body ranges back to transcript ranges', () => {
  const raw = chunked('{"result":[{"a":1},', '{"b":2}]}');
  const r = parseHttpResponse(enc(raw));
  assert.equal(r.status, 200);
  assert.equal(r.headers['transfer-encoding'], 'chunked');
  assert.equal(dec(r.body), '{"result":[{"a":1},{"b":2}]}');
  assert.equal(r.chunks.length, 2);
  const bodyText = dec(r.body), row = '{"b":2}', at = bodyText.indexOf(row);
  const [s, e] = transcriptRange(r.chunks, at, at + row.length);
  assert.equal(raw.slice(s, e), row);
  const first = '{"a":1}', fa = bodyText.indexOf(first);
  assert.equal(raw.slice(...transcriptRange(r.chunks, fa, fa + first.length)), first);
});

test('a range crossing a chunk boundary maps to null', () => {
  const r = parseHttpResponse(enc(chunked('{"result":[{"a"', ':1}]}')));
  const at = dec(r.body).indexOf('{"a":1}');
  assert.equal(transcriptRange(r.chunks, at, at + 7), null);
  assert.equal(transcriptRange(r.chunks, 5, 2), null);
});

test('content-length responses are one chunk', () => {
  const raw = head('Content-Length: 7\r\n') + '{"a":1}';
  const r = parseHttpResponse(enc(raw));
  assert.equal(dec(r.body), '{"a":1}');
  assert.deepEqual(transcriptRange(r.chunks, 0, 7), [raw.length - 7, raw.length]);
});

test('refuses ambiguous or unsupported framing', () => {
  const bad = (raw, code) => assert.throws(() => parseHttpResponse(enc(raw)), new RegExp(`CF_HTTP_FRAMING:${code}`));
  bad(head('Transfer-Encoding: chunked\r\nContent-Length: 3\r\n') + '0\r\n\r\n', 'both-lengths');
  bad(head('Transfer-Encoding: gzip, chunked\r\n') + '0\r\n\r\n', 'transfer-encoding');
  bad(head('Transfer-Encoding: chunked\r\n') + '3;ext=1\r\nabc\r\n0\r\n\r\n', 'chunk-size');
  bad(head('Transfer-Encoding: chunked\r\n') + '3\r\nabcd\r\n0\r\n\r\n', 'chunk-data');
  bad(head('Transfer-Encoding: chunked\r\n') + '3\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n', 'final-chunk');
  bad(head('Transfer-Encoding: chunked\r\n') + '3\r\nabc\r\n', 'chunk-size');
  bad(head('Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n') + '0\r\n\r\n', 'duplicate');
  bad(head('Content-Encoding: br\r\nContent-Length: 1\r\n') + 'x', 'content-encoding');
  bad(head('Content-Length: 5\r\n') + 'abc', 'content-length');
  bad('HTTP/1.0 200 OK\r\n\r\n', 'status-line');
  bad('HTTP/1.1 200 OK\r\nBad Header\r\n\r\n', 'header');
});
