// Bundled into the extension (src/cloudflare-private/browser-client.mjs) by gcp-private-proof/build-browser.mjs.
import { readCloudLink, saveCloudLink } from '../gcp/browser-link.mjs';
import { createCloudflarePrivateClient } from './client.mjs';
import { cloudflareProofFields, sanitizeCloudflarePrivateResult } from './verify-bundle.mjs';
export { sanitizeCloudflarePrivateResult, validateCloudflareAttempt } from './verify-bundle.mjs';
export { createCloudflareLocalSession } from './browser-session.mjs';
export { CF_RUN_STEPS, CF_PAGE_STEPS, CF_API_HOST } from './request.mjs';
export { readCloudLink };

const error = () => new Error('CF_PRIVATE_PROVING_FAILED');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

/** Constructed by the pinned offscreen runner, never by page messages. */
/** `fastSource` + `linkSecret`: the fast check (identity session only), see client.mjs. */
export function createCloudflarePrivateModule({ attempt, workerUrl, onProgress, fastSource, linkSecret }) {
  let url;
  try {
    const location = new URL(globalThis.location.href);
    url = new URL(workerUrl, location);
    if (!['chrome-extension:', 'moz-extension:'].includes(location.protocol) || url.protocol !== location.protocol ||
        url.hostname !== location.hostname || url.port !== location.port || url.origin !== location.origin ||
        url.pathname !== '/cloudflare-private/browser-worker.js' || url.username || url.password || url.search || url.hash) throw error();
  } catch { throw error(); }
  if (onProgress !== undefined && typeof onProgress !== 'function') throw error();
  let worker, pending, closed = false, completedProofs = 0, controller, deadline;
  const terminate = () => {
    worker?.terminate(); worker = undefined;
    if (pending) { const current = pending; pending = undefined; current.cleanup(); current.reject(error()); }
  };
  const progress = () => { try { onProgress?.({ completedProofs }); } catch { /* UI observers cannot affect proof validity. */ } };
  const proveCircuit = (circuitId, inputs, signal) => {
    if (closed || pending || signal.aborted) return Promise.reject(error());
    if (!worker) {
      try {
        worker = new Worker(url, { type: 'module' });
        worker.addEventListener('error', terminate);
        worker.addEventListener('messageerror', terminate);
        worker.addEventListener('message', event => {
          const message = event.data, current = pending;
          try {
            if (!current || !message || message.id !== current.id || !exact(message, ['id', 'ok', 'entry']) || message.ok !== true ||
                message.entry?.circuitId !== current.circuitId) throw error();
            cloudflareProofFields(message.entry);
          } catch { terminate(); return; }
          pending = undefined; current.cleanup(); completedProofs++; progress();
          current.resolve({ circuitId: message.entry.circuitId, proof: message.entry.proof, publicInputs: [...message.entry.publicInputs] });
        });
      } catch { terminate(); return Promise.reject(error()); }
    }
    return new Promise((resolve, reject) => {
      const abort = () => terminate();
      try {
        pending = { id: crypto.randomUUID(), circuitId, resolve, reject, cleanup: () => signal.removeEventListener('abort', abort) };
        signal.addEventListener('abort', abort, { once: true });
        worker.postMessage({ id: pending.id, circuitId, inputs });
      } catch { terminate(); reject(error()); }
    });
  };
  const local = createCloudflarePrivateClient({ attempt, proveCircuit, fastSource, linkSecret,
    saveLink: (binding, secret) => saveCloudLink('cloudflare', binding, secret) });
  const expiresAt = attempt.expiresAt;
  attempt = undefined;
  const clear = () => { linkSecret?.fill(0); closed = true; clearTimeout(deadline); controller?.abort(); terminate(); local.clear(); };
  // Expiry must stop a hung CPU worker, not merely reject its eventual result.
  deadline = setTimeout(clear, Math.max(0, expiresAt - Date.now()));
  return {
    fastCheck: fastSource !== undefined,
    getRevealPlan: (...args) => { if (closed) throw error(); return local.getRevealPlan(...args); },
    clear,
    async prove(witnesses, signal) {
      if (closed || controller || !signal || signal.aborted) { clear(); throw error(); }
      controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener('abort', abort, { once: true });
      progress();
      try { return sanitizeCloudflarePrivateResult(await local.prove(witnesses, controller.signal)); }
      catch { throw error(); }
      finally { signal.removeEventListener('abort', abort); clear(); }
    },
  };
}
