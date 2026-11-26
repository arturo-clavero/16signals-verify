// DOM glue for index.html. All checks live in verify.mjs.
import { describeClaim, parseDropped, verifyCommitment } from './verify.mjs';

const $ = id => document.getElementById(id);
const loadJson = async path => {
  const response = await fetch(new URL(path, import.meta.url));
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return response.json();
};
const text = (tag, value, className) => Object.assign(document.createElement(tag), { textContent: value, className: className ?? '' });

const STATUS = {
  'verified': ['✓ Verified', 'ok'],
  'signature-only': ['✓ Signed by the verifier (public proof bundle not available)', 'warn'],
  'failed': ['✗ Does not verify', 'bad'],
  'not-found': ['✗ No attestation found for this commitment', 'bad'],
};

function render(result) {
  const box = $('result');
  box.replaceChildren();
  const [label, className] = STATUS[result.status] ?? STATUS.failed;
  box.append(text('div', label, `status ${className}`));
  if (result.claim && result.status !== 'failed') box.append(text('p', describeClaim(result), 'claim'));
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
async function bnb(uid) {
  const [{ createPublicClient, http }, { NETWORKS, bnbRegistry }] = await Promise.all([import('viem'), import('../crops/bnb-anchor/anchor.mjs')]);
  const network = new URLSearchParams(location.search).get('network') === 'bsc' ? 'bsc' : 'bsc-testnet';
  const client = createPublicClient({ transport: http(NETWORKS[network].rpcUrl) });
  const registry = bnbRegistry({ uid, client, network });
  const anchor = await registry.anchor();
  if (!anchor) throw new Error('No attestation with this UID on BNB Chain.');
  return { registry, commitment: anchor.attestation.commitment };
}

let anchored = null;

async function run(dropped = {}) {
  $('result').hidden = false;
  $('result').replaceChildren(text('div', 'Checking…', 'status'));
  try {
    const [keys, policy] = await Promise.all([loadJson('./keys.json'), import('../private-proof/gcp/policy.mjs').catch(() => ({}))]);
    const lookup = anchored && !dropped.attestation ? anchored : {};
    render(await verifyCommitment({ dropped, keys, loadJson, gcpBatches: policy.BATCHES, ...lookup }));
  } catch (error) {
    $('result').replaceChildren(text('div', `✗ ${error.message}`, 'status bad'));
  }
}

async function readFile(file) {
  try { await run(parseDropped(await file.text())); }
  catch (error) { $('result').hidden = false; $('result').replaceChildren(text('div', `✗ ${error.message}`, 'status bad')); }
}

async function lookUp(uid) {
  try { anchored = await bnb(uid.trim().toLowerCase()); await run(); }
  catch (error) { anchored = null; $('result').hidden = false; $('result').replaceChildren(text('div', `✗ ${error.message}`, 'status bad')); }
}

$('form').addEventListener('submit', event => { event.preventDefault(); lookUp($('uid').value); });
$('file').addEventListener('change', event => { if (event.target.files[0]) readFile(event.target.files[0]); });
const drop = $('drop');
drop.addEventListener('dragover', event => { event.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', event => {
  event.preventDefault(); drop.classList.remove('over');
  if (event.dataTransfer.files[0]) readFile(event.dataTransfer.files[0]);
});

const initial = new URLSearchParams(location.search).get('uid');
if (initial) { $('uid').value = initial; lookUp(initial); }
