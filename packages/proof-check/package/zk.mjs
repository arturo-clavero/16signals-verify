// Zero-knowledge proofs of a proof package: they verify under the provider's pinned keys and open every signed
// commitment.
//
// Binding (no prover library needed): every circuit is pinned by the provider descriptor (never by the package's own
// `pins`), and every signed commitment digest appears in some proof's public inputs as 32 byte-valued fields in a row.
//
// Verification: UltraHonk with @aztec/bb.js (BB_VERSION), imported lazily and only here. Verifying needs no circuit
// bytecode and almost no setup data: the KZG check uses the BN254 generator [1]_1 and the 128-byte [x]_2 of the Aztec
// ceremony, so both are embedded (192 bytes) instead of the ~71 MB CRS bb.js would otherwise download.
import { pinnedKeyHash, publicBundle, resolvePins } from '../bundle.mjs';
import { fromHex, sha256Hex, strictBase64 } from './bytes.mjs';

export const BB_VERSION = '4.2.0-aztecnr-rc.2';
/** [1]_1 = (1, 2), uncompressed big-endian x || y: the first point of bn254_g1.dat. */
export const CRS_G1_GENERATOR = '0'.repeat(63) + '1' + '0'.repeat(63) + '2';
/** bn254_g2.dat, all 128 bytes. */
export const CRS_G2 =
  '0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c122febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e5504fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4';
const OPTIONS = Object.freeze({ verifierTarget: 'noir-recursive' });

class BindingError extends Error {}

/** Every 32-byte digest that appears as 32 consecutive byte-valued fields. */
function digestsIn(fields) {
  const out = new Set();
  for (let i = 0; i + 32 <= fields.length; i++) {
    const window = fields.slice(i, i + 32);
    if (window.every((field) => field <= 255n))
      out.add(window.map((field) => field.toString(16).padStart(2, '0')).join(''));
  }
  return out;
}

/** The ZK bundle of a proof group: the first run that carries one. */
function groupBundle(group) {
  const carrier = group.find(({ run }) => run.zk !== null && run.zk !== undefined);
  if (!carrier) return null;
  try {
    return publicBundle(carrier.run.zk);
  } catch {
    throw new BindingError('the ZK bundle is malformed');
  }
}

function bind(descriptor, trusted, pins, groups) {
  // A provider with pinned circuits always hides its values behind ZK proofs. A leaf's kind is not signed, so a commit
  // leaf relabelled `reveal` and hidden would drop its digest out of the binding: its v2 runs must carry commit
  // leaves, and every proof must carry a bundle.
  const required = Boolean(trusted);
  const proofs = [];
  let commitments = 0;
  groups.forEach((group, g) => {
    if (required) {
      const bare = group.find(
        ({ payload, resolved }) => payload?.v === 2 && !resolved.committed.length,
      );
      if (bare)
        throw new BindingError(
          `session ${String(bare.payload.sessionId)} commits no values; its hidden values are bound by no proof`,
        );
    }
    const bundle = groupBundle(group);
    const digests = group.flatMap(({ resolved }) => resolved.committed.map((c) => c.digest));
    commitments += digests.length;
    if (!bundle && required)
      throw new BindingError(
        `proof ${g + 1} carries no ZK proofs; ${descriptor.id} proofs always do`,
      );
    if (!bundle) {
      if (digests.length)
        throw new BindingError(
          `proof ${g + 1} hides ${digests.length} values but carries no ZK proofs`,
        );
      return;
    }
    if (!trusted) throw new BindingError(`${descriptor.id} has no pinned circuits`);
    if (descriptor.kind && bundle.kind !== descriptor.kind)
      throw new BindingError(`the ZK bundle is ${bundle.kind}, not ${descriptor.kind}`);
    const fields = bundle.proofs.map((entry) => {
      const values = entry.publicInputs.map(BigInt);
      if (values.some((value) => value > 0xffffffffffffffffn))
        throw new BindingError(`${entry.circuitId}: a public input is out of range`);
      const sha = pinnedKeyHash(trusted[entry.circuitId]);
      if (!sha)
        throw new BindingError(`${entry.circuitId} is not a pinned ${descriptor.id} circuit`);
      if (pins?.[entry.circuitId] !== sha)
        throw new BindingError(
          `the package pins ${entry.circuitId} to ${String(pins?.[entry.circuitId])}, the provider to ${sha}`,
        );
      proofs.push({ entry, sha, values });
      return values;
    });
    const opened = new Set(fields.flatMap((values) => [...digestsIn(values)]));
    const missing = digests.filter((digest) => !opened.has(digest));
    if (missing.length)
      throw new BindingError(
        `${missing.length} signed commitment(s) are opened by no proof (first ${missing[0].slice(0, 16)}…)`,
      );
  });
  return { proofs, commitments };
}

let bbPromise = null;
const defaultLoadBb = () => import('@aztec/bb.js');

/** One Barretenberg instance per page or process, set up with the 192-byte verifier SRS (no CRS download). */
async function barretenberg(loadBb) {
  if (!bbPromise) {
    bbPromise = (async () => {
      const bb = await loadBb();
      const { Barretenberg, BackendType } = bb;
      const original = Barretenberg.prototype.initSRSChonk;
      Barretenberg.prototype.initSRSChonk = async function initVerifierSrs() {
        await this.srsInitSrs({
          pointsBuf: fromHex(CRS_G1_GENERATOR),
          numPoints: 1,
          g2Point: fromHex(CRS_G2),
        });
      };
      try {
        const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
        return { api, verifier: new bb.UltraHonkVerifierBackend(api) };
      } finally {
        Barretenberg.prototype.initSRSChonk = original;
      }
    })();
    bbPromise.catch(() => {
      bbPromise = null;
    });
  }
  return bbPromise;
}

/** Releases the shared Barretenberg instance (CLI exit, tests). */
export async function closeZk() {
  const pending = bbPromise;
  bbPromise = null;
  if (pending) {
    try {
      await (await pending).api.destroy();
    } catch {
      /* already gone */
    }
  }
}

const hex32 = (n) => `0x${n.toString(16).padStart(64, '0')}`;

/**
 * Options: `descriptor`, `pins` (the package's), `groups` ([{ run, payload, resolved }] per proof), `loadBb` (default
 * `import('@aztec/bb.js')`), `verificationKey(circuitId, sha256)` -> Uint8Array | null, `vks` (circuit id -> base64, the
 * package's own). Every key is checked against the provider's pin. Returns `{ ok, detail, reason? }`.
 */
export async function checkZk({
  descriptor,
  pins,
  groups,
  loadBb = defaultLoadBb,
  verificationKey,
  vks,
}) {
  const trusted = (await resolvePins(descriptor).catch(() => undefined))?.circuits;
  let bound;
  try {
    bound = bind(descriptor, trusted, pins, groups);
  } catch (error) {
    if (!(error instanceof BindingError)) throw error;
    return { ok: false, detail: error.message };
  }
  if (!bound.proofs.length)
    return {
      ok: null,
      reason: 'not-applicable',
      detail: 'nothing is hidden behind a zero-knowledge proof',
    };
  let zk;
  try {
    zk = await barretenberg(loadBb);
  } catch {
    return {
      ok: null,
      detail: `the proofs open the ${bound.commitments} signed commitments; verifying them needs @aztec/bb.js@${BB_VERSION}`,
    };
  }
  const keys = new Map();
  let verified = 0;
  for (const { entry, sha, values } of bound.proofs) {
    if (!keys.has(sha)) {
      const offered = vks?.[entry.circuitId];
      const bytes =
        (await verificationKey?.(entry.circuitId, sha)) ??
        (typeof offered === 'string' ? strictBase64(offered) : null);
      if (!bytes)
        return {
          ok: null,
          detail: `the proofs open the signed commitments; the verification key for ${entry.circuitId} was not available`,
        };
      if ((await sha256Hex(bytes)) !== sha)
        return {
          ok: false,
          detail: `the verification key offered for ${entry.circuitId} is not the pinned one`,
        };
      keys.set(sha, bytes);
    }
    const proof = strictBase64(entry.proof, 32768);
    const ok =
      proof !== null &&
      (await zk.verifier
        .verifyProof(
          { proof, publicInputs: values.map(hex32), verificationKey: keys.get(sha) },
          OPTIONS,
        )
        .catch(() => false));
    if (!ok)
      return {
        ok: false,
        detail: `proof ${verified + 1} (${entry.circuitId}) does not verify under its pinned key`,
      };
    verified += 1;
  }
  return {
    ok: true,
    detail: `${verified} proofs verify under the pinned keys and open the ${bound.commitments} signed commitments`,
  };
}
