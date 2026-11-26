/**
 * Private inputs for one Cloudflare proof target (verify-bundle.mjs cloudflareTargets). `openings` maps a commitment
 * hash (hex) to its preimage bytes || 16-byte blinder, already matched to the native selections and hashed.
 */
import { CF_CIRCUITS } from './verify-bundle.mjs';

const fail = () => { throw new Error('CF_PRIVATE_CLIENT_INVALID'); };

export function eraseCloudflareInputs(value) {
  if (!value || typeof value !== 'object') return;
  if (value instanceof Uint8Array) { value.fill(0); return; }
  for (const key of Object.keys(value)) { if (typeof value[key] === 'number') value[key] = 0; else eraseCloudflareInputs(value[key]); }
}

export function cloudflareCircuitInputs({ circuitId: id, publicInputs: values }, openings) {
  if (!Object.hasOwn(CF_CIRCUITS, id) || values.length !== CF_CIRCUITS[id][2]) fail();
  const [count, capacity] = CF_CIRCUITS[id], take = (start, n) => values.slice(start, start + n);
  const opening = (hash, length, size) => {
    const bytes = Array(size).fill(0);
    if (length) {
      const digest = hash.map(b => b.toString(16).padStart(2, '0')).join(''), value = openings.get(digest);
      if (!(value instanceof Uint8Array) || value.length !== length + 16 || value.length > size) fail();
      value.forEach((b, i) => { bytes[i] = b; });
    }
    return bytes;
  };
  if (id === 'header-v1' || id === 'cf-json-wide-v1') {
    const hash = take(0, 32), length = values[32], inputs = id === 'header-v1' ? { commitment: hash, length } : { hash, length, kind: values[33] };
    inputs.preimage = opening(hash, length, capacity + 16);
    return inputs;
  }
  if (id === 'cf-actor-v1') {
    const identity_hash = take(0, 32), identity_length = values[32];
    const hashes = Array.from({ length: 8 }, (_, i) => take(33 + i * 32, 32)), lengths = take(33 + 256, 8);
    return { identity_hash, identity_length, hashes, lengths, identity_preimage: opening(identity_hash, identity_length, 80),
      preimages: hashes.map((h, i) => opening(h, lengths[i], 80)) };
  }
  const hashes = Array.from({ length: count }, (_, i) => take(i * 32, 32)), lengths = take(count * 32, count);
  if (id === 'cf-identity-refresh-v1') return { hashes, lengths, old_preimage: opening(hashes[0], lengths[0], 80), new_preimage: opening(hashes[1], lengths[1], 80) };
  const inputs = { hashes, lengths };
  if (id !== 'headers-small-v1' && id !== 'cf-headers-v1') inputs.kinds = take(count * 33, count);
  inputs.preimages = hashes.map((h, i) => opening(h, lengths[i], capacity + 16));
  return inputs;
}
