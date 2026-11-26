// Verifier receipts (servers/verifier README, "Signed receipts"): a compact JWS, EdDSA (Ed25519), header
// {"alg":"EdDSA","kid":"did:web:<host>#<fragment>","typ":"tlsn-receipt+jws"}, key from the issuer's did:web document.
// The payload is parsed only after the signature verifies and is never re-serialised.
import { base64Url, isHex64, isRecord, utf8, verifyEd25519 } from './bytes.mjs';

export const RECEIPT_TYP = 'tlsn-receipt+jws';
const KID = /^(did:web:[^#\s]+)#([A-Za-z0-9._~%-]+)$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_JWS = 8192;

export class ReceiptError extends Error {}

function parseJson(bytes, what) {
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!isRecord(value)) throw new Error('not an object');
    return value;
  } catch {
    throw new ReceiptError(`the receipt ${what} is not a JSON object`);
  }
}

/** The receipt's parts before any verification (the header names the key). */
export function splitReceipt(jws) {
  if (typeof jws !== 'string' || jws.length > MAX_JWS)
    throw new ReceiptError('the receipt is not a compact JWS');
  const parts = jws.split('.');
  if (parts.length !== 3) throw new ReceiptError('the receipt is not a compact JWS');
  const [header, payload, signature] = parts.map(base64Url);
  if (!header || !payload || !signature)
    throw new ReceiptError('the receipt is not unpadded base64url');
  const parsed = parseJson(header, 'header');
  if (
    parsed.alg !== 'EdDSA' ||
    parsed.typ !== RECEIPT_TYP ||
    typeof parsed.kid !== 'string' ||
    !KID.test(parsed.kid)
  ) {
    throw new ReceiptError(
      `the receipt header is not {alg: EdDSA, typ: ${RECEIPT_TYP}, kid: did:web:<host>#<key>}`,
    );
  }
  return {
    header: parsed,
    payloadBytes: payload,
    signature,
    signingInput: utf8(`${parts[0]}.${parts[1]}`),
  };
}

/** The DID a kid belongs to (`did:web:<host>`). */
export const didOf = (kid) => KID.exec(kid ?? '')?.[1] ?? null;

/** The did:web document URL for a DID (`did:web:<host>` -> `https://<host>/.well-known/did.json`). */
export function didWebUrl(did) {
  const m = /^did:web:([^:#\s]+)((?::[^:#\s]+)*)$/.exec(did ?? '');
  if (!m) return null;
  const host = decodeURIComponent(m[1]);
  return m[2]
    ? `https://${host}/${m[2].slice(1).split(':').map(decodeURIComponent).join('/')}/did.json`
    : `https://${host}/.well-known/did.json`;
}

/** The Ed25519 key `kid` names in a DID document, as 32 raw bytes. It must be listed in `assertionMethod`. */
export function receiptKey(didDocument, kid) {
  const did = didOf(kid);
  if (!isRecord(didDocument)) throw new ReceiptError(`no DID document for ${did}`);
  if (didDocument.id !== did)
    throw new ReceiptError(
      `the DID document is ${String(didDocument.id)}, the receipt names ${did}`,
    );
  const named = (id) =>
    id === kid || (typeof id === 'string' && id.startsWith('#') && `${did}${id}` === kid);
  const methods = Array.isArray(didDocument.verificationMethod)
    ? didDocument.verificationMethod
    : [];
  const method = methods.find((entry) => isRecord(entry) && named(entry.id));
  if (!method) throw new ReceiptError(`the DID document publishes no key ${kid}`);
  const assertion = Array.isArray(didDocument.assertionMethod) ? didDocument.assertionMethod : [];
  if (!assertion.some((entry) => named(isRecord(entry) ? entry.id : entry)))
    throw new ReceiptError(`${kid} is not an assertion key`);
  const jwk = method.publicKeyJwk;
  if (!isRecord(jwk) || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || 'd' in jwk)
    throw new ReceiptError(`${kid} is not a public Ed25519 key`);
  const x = base64Url(jwk.x);
  if (!x || x.length !== 32) throw new ReceiptError(`${kid} is not a 32-byte Ed25519 key`);
  return { key: x, x: jwk.x };
}

function parsePayload(bytes) {
  const p = parseJson(bytes, 'payload');
  const ok =
    (p.v === 1 || p.v === 2) &&
    typeof p.serverName === 'string' &&
    typeof p.sessionId === 'string' &&
    (p.proofId === undefined || typeof p.proofId === 'string') &&
    typeof p.verifiedAt === 'string' &&
    RFC3339.test(p.verifiedAt) &&
    Number.isFinite(Date.parse(p.verifiedAt)) &&
    typeof p.tlsnVersion === 'string' &&
    isHex64(p.root) &&
    Number.isSafeInteger(p.leafCount) &&
    p.leafCount > 0;
  if (!ok) throw new ReceiptError('the signed payload is not a v1/v2 verifier receipt');
  return p;
}

/**
 * Verifies one receipt against the issuer's DID document. Returns `{ ok: true, payload, kid, x }`,
 * `{ ok: false, reason }`, or `{ ok: null, reason }` when the platform cannot run Ed25519.
 */
export async function verifyReceipt(jws, didDocument) {
  let parts, key;
  try {
    parts = splitReceipt(jws);
    key = receiptKey(didDocument, parts.header.kid);
  } catch (error) {
    if (error instanceof ReceiptError) return { ok: false, reason: error.message };
    throw error;
  }
  const kid = parts.header.kid;
  const verdict = await verifyEd25519(key.key, parts.signingInput, parts.signature);
  if (verdict === null)
    return { ok: null, reason: 'this platform has no Ed25519 in WebCrypto', kid };
  if (!verdict) return { ok: false, reason: `the signature does not verify under ${kid}`, kid };
  try {
    return { ok: true, payload: parsePayload(parts.payloadBytes), kid, x: key.x };
  } catch (error) {
    if (error instanceof ReceiptError) return { ok: false, reason: error.message, kid };
    throw error;
  }
}

/** The kid and payload without checking the signature: for display and grouping only, never trusted. */
export function unverifiedReceipt(jws) {
  try {
    const parts = splitReceipt(jws);
    return { kid: parts.header.kid, payload: parsePayload(parts.payloadBytes) };
  } catch {
    return null;
  }
}
