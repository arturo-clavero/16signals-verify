// Byte helpers for proof-package checks: only what browsers and Node share (WebCrypto, TextEncoder, atob/btoa).
import { toHex } from '../commitment.mjs';

const HEX = /^(?:[0-9a-f]{2})+$/;
const HEX64 = /^[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export { toHex };
export const isHex64 = value => typeof value === 'string' && HEX64.test(value);
export const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const utf8 = text => new TextEncoder().encode(text);

export function fromHex(value) {
  if (typeof value !== 'string' || !HEX.test(value)) throw new TypeError('expected lowercase hex');
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}

export function toBase64(bytes) {
  let binary = '';
  for (let at = 0; at < bytes.length; at += 8192) binary += String.fromCharCode(...bytes.subarray(at, at + 8192));
  return btoa(binary);
}

/** Canonical padded base64 to bytes, or null (one spelling per value). */
export function strictBase64(value, maxChars = 8 * 1024 * 1024) {
  if (typeof value !== 'string' || value.length > maxChars || !BASE64.test(value)) return null;
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return toBase64(bytes) === value ? bytes : null;
}

/** Unpadded base64url to bytes, or null. */
export function base64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  const bytes = strictBase64(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4));
  return bytes && toBase64(bytes).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_') === value ? bytes : null;
}

function subtle() {
  const value = globalThis.crypto?.subtle;
  if (!value) throw new Error('this platform has no WebCrypto (crypto.subtle)');
  return value;
}

export async function sha256(...parts) {
  return new Uint8Array(await subtle().digest('SHA-256', parts.length === 1 ? parts[0] : concat(...parts)));
}

export const sha256Hex = async (...parts) => toHex(await sha256(...parts));

/** Ed25519 through WebCrypto: true or false, or null when the platform has no Ed25519 ("could not check" is not "invalid"). */
export async function verifyEd25519(publicKey32, message, signature64) {
  if (!(publicKey32 instanceof Uint8Array) || publicKey32.length !== 32) return false;
  if (!(signature64 instanceof Uint8Array) || signature64.length !== 64) return false;
  let key;
  try {
    key = await subtle().importKey('raw', publicKey32, { name: 'Ed25519' }, false, ['verify']);
  } catch (error) {
    if (error?.name === 'NotSupportedError' || /not supported|unrecognized/i.test(String(error?.message))) return null;
    return false;
  }
  try {
    return await subtle().verify({ name: 'Ed25519' }, key, signature64, message);
  } catch {
    return false;
  }
}
