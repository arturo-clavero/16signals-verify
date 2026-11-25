// Extension-origin storage only: one random opening per provider, never a transcript or identity.
const valid = (provider, binding, secret) => ['gcp', 'aws'].includes(provider) &&
  /^[0-9a-f]{64}$/.test(binding) && secret instanceof Uint8Array && secret.length === (provider === 'gcp' ? 32 : 16);

async function database() {
  if (!['chrome-extension:', 'moz-extension:'].includes(globalThis.location?.protocol)) throw new Error('PRIVATE_LINK_UNAVAILABLE');
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('16signals-cloud-link', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('links');
    request.onerror = () => reject(new Error('PRIVATE_LINK_UNAVAILABLE'));
    request.onblocked = () => reject(new Error('PRIVATE_LINK_UNAVAILABLE'));
    request.onsuccess = () => resolve(request.result);
  });
}

export async function readCloudLink(provider, binding) {
  let db;
  try {
    db = await database();
    const value = await new Promise((resolve, reject) => {
      const request = db.transaction('links').objectStore('links').get(provider);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('PRIVATE_LINK_UNAVAILABLE'));
    });
    return value?.binding === binding && valid(provider, binding, value.secret) ? value.secret : null;
  } catch { return null; }
  finally { db?.close(); }
}

export async function saveCloudLink(provider, binding, secret) {
  let db;
  try {
    if (!valid(provider, binding, secret)) return;
    db = await database();
    await new Promise((resolve, reject) => {
      const transaction = db.transaction('links', 'readwrite');
      transaction.oncomplete = resolve;
      transaction.onerror = transaction.onabort = () => reject(new Error('PRIVATE_LINK_UNAVAILABLE'));
      transaction.objectStore('links').put({ binding, secret }, provider);
    });
  } catch { /* Storage unavailable means the next check must be full. */ }
  finally { db?.close(); }
}
