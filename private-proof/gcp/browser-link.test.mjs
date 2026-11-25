import assert from 'node:assert/strict';
import test from 'node:test';
import { readCloudLink, saveCloudLink } from './browser-link.mjs';

// An IDB double models its structured-clone boundary and transaction completion.
test('link storage stays extension-local, copies only random openings, and tolerates unavailable storage', async () => {
  const descriptors = Object.fromEntries(['location', 'indexedDB'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const records = new Map(); let opens = 0;
  const binding = 'ab'.repeat(32), secret = new Uint8Array(32).fill(7);
  try {
    Object.defineProperty(globalThis, 'location', { configurable: true, value: { protocol: 'https:' } });
    Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: { open() { opens++; throw Error('Not available'); } } });
    await saveCloudLink('gcp', binding, secret); assert.equal(await readCloudLink('gcp', binding), null); assert.equal(opens, 0);
    Object.defineProperty(globalThis, 'location', { configurable: true, value: { protocol: 'chrome-extension:' } });
    await saveCloudLink('gcp', binding, secret); assert.equal(await readCloudLink('gcp', binding), null);
    globalThis.indexedDB.open = () => {
      const request = {};
      queueMicrotask(() => { request.result = { close() {}, transaction() {
        const transaction = { objectStore: () => ({
          put(value, provider) { records.set(provider, structuredClone(value)); queueMicrotask(() => transaction.oncomplete()); },
          get(provider) { const result = {}; queueMicrotask(() => { result.result = structuredClone(records.get(provider)); result.onsuccess(); }); return result; },
        }) }; return transaction;
      } }; request.onsuccess(); }); return request;
    };
    await saveCloudLink('gcp', binding, secret); secret.fill(0);
    assert.deepEqual(Object.keys(records.get('gcp')).sort(), ['binding', 'secret']);
    const recovered = await readCloudLink('gcp', binding); assert.equal(recovered[0], 7); recovered.fill(0);
    assert.equal((await readCloudLink('gcp', binding))[0], 7);
    assert.equal(await readCloudLink('gcp', 'cd'.repeat(32)), null);
    await saveCloudLink('aws', binding, new Uint8Array(32)); assert.equal(records.has('aws'), false);
    records.set('gcp', { binding, secret: new Uint8Array(16) }); assert.equal(await readCloudLink('gcp', binding), null);
  } finally {
    for (const key of Object.keys(descriptors)) if (descriptors[key]) Object.defineProperty(globalThis, key, descriptors[key]); else delete globalThis[key];
  }
});
