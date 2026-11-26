// Test helper: a native-verifier-shaped receipt for a session plan, with real SHA256(bytes || blinder) commitments,
// plus the prover's openings (hash -> { bytes, blinder }). Synthetic data only.
import { createHash, randomBytes } from 'node:crypto';

export function receiptFor({ sent, recv, plan, expected, method = 'CLOUDFLARE_ACCOUNT', serverName = 'api.cloudflare.com' }) {
  const openings = new Map(), results = [];
  const direction = (bytes, ranges, type) => {
    const visible = new Uint8Array(bytes.length);
    for (const range of ranges) {
      const slice = bytes.subarray(range.start, range.end);
      if (range.handler.action.kind === 'REVEAL') {
        visible.set(slice, range.start);
        results.push({ type, part: range.handler.part, action: { kind: 'REVEAL' }, value: String.fromCharCode(...slice) });
      } else {
        const blinder = randomBytes(16);
        const hash = createHash('sha256').update(slice).update(blinder).digest('hex');
        openings.set(hash, { bytes: Uint8Array.from(slice), blinder: Uint8Array.from(blinder) });
        results.push({ type, part: range.handler.part, action: { kind: 'HASH', algorithm: 'SHA256' }, value: hash });
      }
    }
    return String.fromCharCode(...visible);
  };
  const sentText = direction(sent, plan.sentRangesWithHandlers, 'SENT');
  const recvText = direction(recv, plan.recvRangesWithHandlers, 'RECV');
  const receipt = {
    session: { id: expected.sessionId, proofId: expected.proofId, pluginSha256: expected.pluginSha256, nonceMac: expected.nonceMac,
      step: expected.step, method, mode: 'Proxy' },
    server_name: serverName,
    config: { sent: plan.sentRangesWithHandlers, recv: plan.recvRangesWithHandlers },
    results,
    transcript: { sent: sentText, recv: recvText, sent_length: sent.length, recv_length: recv.length },
  };
  return { receipt, openings };
}
