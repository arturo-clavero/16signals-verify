// The verify page as a drop-in: mountVerify(el, config) renders the lookup form, file drop and result into el.
// All checks live in packages/proof-check; providers, keys and registries come from the config (verify.config.json).
import { describeClaim, parseDropped, resolveConfig, verifyCommitment } from '../packages/proof-check/index.mjs';

const readJson = async url => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response.json();
};
const text = (tag, value, className) => Object.assign(document.createElement(tag), { textContent: value, className: className ?? '' });

const STATUS = {
  'verified': ['✓ Verified', 'ok'],
  'signature-only': ['✓ Signed by the verifier (public proof bundle not available)', 'warn'],
  'failed': ['✗ Does not verify', 'bad'],
  'not-found': ['✗ No attestation found for this commitment', 'bad'],
};

function render(box, result, providers) {
  box.replaceChildren();
  const [label, className] = STATUS[result.status] ?? STATUS.failed;
  box.append(text('div', label, `status ${className}`));
  if (result.claim && result.status !== 'failed') box.append(text('p', describeClaim(result, providers), 'claim'));
  const details = document.createElement('details');
  details.append(text('summary', 'Details'));
  const checks = document.createElement('ul');
  for (const check of result.checks ?? []) checks.append(text('li', `${check.ok ? '✓' : '✗'} ${check.label}`));
  details.append(text('p', 'Checked in this browser:'), checks);
  const trust = document.createElement('ul');
  for (const line of result.restsOnSignature ?? []) trust.append(text('li', line));
  details.append(text('p', 'Taken from the verifier’s signature:'), trust);
  if (result.verifier) details.append(text('p', `Verifier key: ${result.verifier}`));
  if (result.commitment) { const p = text('p', 'Commitment: '); p.append(text('code', result.commitment)); details.append(p); }
  box.append(details);
  box.hidden = false;
}

// An attestation anchored on BNB Chain (BAS), read from a public RPC. A file dropped afterwards can add its bundle.
async function bnb(entry, uid) {
  const [{ createPublicClient, http }, { NETWORKS, bnbRegistry }] = await Promise.all([import('viem'), import(entry.module)]);
  const network = new URLSearchParams(location.search).get('network') === 'bsc' ? 'bsc' : entry.network ?? 'bsc-testnet';
  const client = createPublicClient({ transport: http(NETWORKS[network].rpcUrl) });
  const registry = bnbRegistry({ uid, client, network });
  const anchor = await registry.anchor();
  if (!anchor) throw new Error('No attestation with this UID on BNB Chain.');
  return { registries: [registry], commitment: anchor.attestation.commitment };
}

/**
 * Renders the verify UI into `el`. `config` is a verify.config.json URL, or a config object whose paths resolve against
 * the page URL (providers may also be descriptor objects and keys a keys object). A `bnb` registry entry adds the UID
 * lookup form.
 */
export async function mountVerify(el, config = './verify.config.json') {
  const resolved = typeof config === 'string' || config instanceof URL
    ? await resolveConfig(await readJson(new URL(config, location.href)), new URL(config, location.href), { readJson })
    : await resolveConfig(config, location.href, { readJson });
  const { providers, keys } = resolved;
  const anchorEntry = resolved.registries.find(entry => entry?.type === 'bnb');

  const result = Object.assign(document.createElement('section'), { className: 'result', hidden: true });
  result.setAttribute('aria-live', 'polite');
  const show = (value, className) => { result.hidden = false; result.replaceChildren(text('div', value, `status ${className ?? ''}`.trim())); };
  const file = Object.assign(document.createElement('input'), { type: 'file', accept: 'application/json,.json' });
  const drop = text('label', `${anchorEntry ? 'Or drop' : 'Drop'} an attestation file (with its public proof bundle) here, or `, 'drop');
  drop.append(file);

  let anchored = null;
  async function run(dropped = {}) {
    show('Checking…');
    try {
      const lookup = anchored && !dropped.attestation ? anchored : {};
      render(result, await verifyCommitment({ dropped, keys, providers, ...lookup }), providers);
    } catch (error) { show(`✗ ${error.message}`, 'bad'); }
  }
  async function readFile(picked) {
    try { await run(parseDropped(await picked.text())); } catch (error) { show(`✗ ${error.message}`, 'bad'); }
  }

  file.addEventListener('change', event => { if (event.target.files[0]) readFile(event.target.files[0]); });
  drop.addEventListener('dragover', event => { event.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', event => {
    event.preventDefault(); drop.classList.remove('over');
    if (event.dataTransfer.files[0]) readFile(event.dataTransfer.files[0]);
  });

  const parts = [];
  if (anchorEntry) {
    const form = document.createElement('form');
    const uid = Object.assign(document.createElement('input'), { type: 'text', placeholder: 'BNB Chain attestation UID (0x + 64 hex)',
      autocomplete: 'off', spellcheck: false });
    uid.setAttribute('aria-label', 'BNB Chain attestation UID');
    form.append(uid, Object.assign(document.createElement('button'), { type: 'submit', textContent: 'Look up' }));
    const lookUp = async value => {
      try { anchored = await bnb(anchorEntry, value.trim().toLowerCase()); await run(); }
      catch (error) { anchored = null; show(`✗ ${error.message}`, 'bad'); }
    };
    form.addEventListener('submit', event => { event.preventDefault(); lookUp(uid.value); });
    parts.push(form);
    const initial = new URLSearchParams(location.search).get('uid');
    if (initial) { uid.value = initial; lookUp(initial); }
  }
  el.replaceChildren(...parts, drop, result);
}
