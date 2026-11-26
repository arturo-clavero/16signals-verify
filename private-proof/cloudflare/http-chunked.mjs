/**
 * HTTP/1.1 response framing for api.cloudflare.com transcripts. Cloudflare answers with `Transfer-Encoding: chunked`
 * (AWS answered with Content-Length), so the JSON body is split by chunk-size lines inside the received bytes.
 *
 * parseHttpResponse(bytes) -> { status, headers, headEnd, body, chunks }
 *   status   numeric status code from the status line.
 *   headers  lower-cased header names -> value (last one wins; duplicates of framing headers are refused).
 *   headEnd  transcript offset just after the blank line ending the head.
 *   body     the decoded body bytes (Uint8Array).
 *   chunks   [{ start, end, bodyStart }]: each chunk's data range in transcript offsets and where it starts in `body`.
 *            A Content-Length response is one chunk.
 * transcriptRange(chunks, bodyStart, bodyEnd) -> [start, end) in the transcript, or null when the body range crosses
 *   a chunk boundary (a row split by framing is not provable as one contiguous transcript range; the caller drops it).
 *
 * Strict on purpose: unknown transfer codings, chunk extensions, trailers, compression and bytes after the final chunk
 * are refused (CF_HTTP_FRAMING), so the prover and the verifier read the same body.
 */
const CRLF = [13, 10];
const fail = what => { throw new Error(`CF_HTTP_FRAMING:${what}`); };
const ascii = (bytes, a, b) => String.fromCharCode(...bytes.subarray(a, b));

function lineEnd(bytes, from) {
  for (let i = from; i + 1 < bytes.length; i++) if (bytes[i] === CRLF[0] && bytes[i + 1] === CRLF[1]) return i;
  return -1;
}

export function parseHttpResponse(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const statusEnd = lineEnd(bytes, 0);
  if (statusEnd < 0) fail('status-line');
  const status = /^HTTP\/1\.1 ([1-5][0-9]{2})(?: .*)?$/.exec(ascii(bytes, 0, statusEnd));
  if (!status) fail('status-line');
  const headers = {};
  let at = statusEnd + 2;
  for (;;) {
    const end = lineEnd(bytes, at);
    if (end < 0) fail('head');
    if (end === at) { at += 2; break; }
    const line = ascii(bytes, at, end), colon = line.indexOf(':');
    if (colon <= 0 || /[\s]/.test(line.slice(0, colon))) fail('header');
    const name = line.slice(0, colon).toLowerCase();
    if (['transfer-encoding', 'content-length', 'content-encoding'].includes(name) && Object.hasOwn(headers, name)) fail(`duplicate:${name}`);
    headers[name] = line.slice(colon + 1).trim();
    at = end + 2;
  }
  const headEnd = at;
  if (headers['content-encoding'] && headers['content-encoding'] !== 'identity') fail('content-encoding');
  const te = headers['transfer-encoding'], cl = headers['content-length'];
  if (te !== undefined && cl !== undefined) fail('both-lengths');
  if (te !== undefined) {
    if (te.toLowerCase() !== 'chunked') fail('transfer-encoding');
    const chunks = [], parts = [];
    let bodyStart = 0;
    for (;;) {
      const end = lineEnd(bytes, at);
      if (end < 0) fail('chunk-size');
      const sizeText = ascii(bytes, at, end);
      if (!/^[0-9a-fA-F]{1,8}$/.test(sizeText)) fail('chunk-size');
      const size = parseInt(sizeText, 16), start = end + 2;
      if (size === 0) {
        if (bytes.length !== start + 2 || bytes[start] !== 13 || bytes[start + 1] !== 10) fail('final-chunk');
        break;
      }
      if (start + size + 2 > bytes.length || bytes[start + size] !== 13 || bytes[start + size + 1] !== 10) fail('chunk-data');
      chunks.push({ start, end: start + size, bodyStart });
      parts.push(bytes.subarray(start, start + size));
      bodyStart += size;
      at = start + size + 2;
    }
    const body = new Uint8Array(bodyStart);
    parts.reduce((offset, part) => (body.set(part, offset), offset + part.length), 0);
    return { status: Number(status[1]), headers, headEnd, body, chunks };
  }
  if (cl === undefined || !/^[0-9]{1,9}$/.test(cl) || headEnd + Number(cl) !== bytes.length) fail('content-length');
  return { status: Number(status[1]), headers, headEnd, body: bytes.slice(headEnd), chunks: [{ start: headEnd, end: bytes.length, bodyStart: 0 }] };
}

export function transcriptRange(chunks, bodyStart, bodyEnd) {
  if (!(Number.isSafeInteger(bodyStart) && Number.isSafeInteger(bodyEnd) && bodyStart <= bodyEnd)) return null;
  for (const chunk of chunks) {
    const length = chunk.end - chunk.start;
    if (bodyStart >= chunk.bodyStart && bodyEnd <= chunk.bodyStart + length)
      return [chunk.start + bodyStart - chunk.bodyStart, chunk.start + bodyEnd - chunk.bodyStart];
  }
  return null;
}
