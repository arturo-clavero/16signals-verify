/**
 * Local, unproven discovery and the choice of what to prove. Nothing here is sent to the site that asked for the proof.
 *
 * discoverCloudflare({ read, userId, accountId, now }) reads the candidate's own successful non-view rows over the
 *   lookback (newest first, 1,000 per read, cursor), within CF_DISCOVERY budget. `read(request)` performs an unproven
 *   GET and returns the parsed JSON. A failed later read degrades (fewer rows); a failed first read throws.
 * selectCloudflareWindows(rows, userId, now) packs the rows into up to CF_PAGE_STEPS.length disjoint windows of at most
 *   CF_PAGE_LIMIT_MAX consecutive rows (the rows the page request will return), and keeps the windows with the most
 *   distinct (skill group, day) pairs. Returns [{ since, before, limit }], newest window first.
 * selectCloudflareRows(rows, mappable, userId, issuedAt) picks, inside one proven page, up to CF_PAGE_ROW_CAP rows to
 *   prove: catalog evidence that fits the row grammar and size limits and lies inside one chunk; new (group, day)
 *   pairs first. Rows before the last pick that are not picked are hidden whole, so the picks stop at the first row
 *   that cannot be hidden.
 */
import { buildCloudflareRequest, CF_PAGE_LIMIT_MAX, CF_PAGE_STEPS, CF_WINDOW_DAYS } from './request.mjs';
import { CF_PAGE_ROW_CAP, CF_SKIPPED_ROW_MAX } from './session.mjs';
import { countsAsEvidence, cloudflareCatalogOperation } from './skill-groups.mjs';
import { rowPieces } from './row-structure.mjs';

export const CF_DISCOVERY = Object.freeze({ reads: 5, rowsPerRead: 1000, rowsMax: 5000 });
const DAY_MS = 864e5;
const iso = ms => new Date(ms).toISOString();

export async function discoverCloudflare({ read, token, userId, accountId, now = Date.now() }) {
  const since = iso(now - CF_WINDOW_DAYS * DAY_MS), before = iso(now), rows = [];
  let cursor;
  for (let i = 0; i < CF_DISCOVERY.reads; i++) {
    let page;
    try {
      page = await read(buildCloudflareRequest({ kind: 'page', token, accountId, userId, since, before, limit: CF_DISCOVERY.rowsPerRead, cursor }));
      if (page?.success !== true || !Array.isArray(page.result)) throw new Error('CF_DISCOVERY_FAILED');
    } catch (error) {
      if (i === 0) throw new Error('CF_DISCOVERY_FAILED');
      break; // A later read failing only means fewer rows.
    }
    rows.push(...page.result);
    cursor = page.result_info?.cursor;
    if (!cursor || !page.result.length || rows.length >= CF_DISCOVERY.rowsMax) break;
  }
  return rows;
}

/** A row the prover could prove: own catalog evidence whose bytes fit the grammar and the piece size limits. */
export function provableRow(row, userId, issuedAt) {
  if (!countsAsEvidence(row, userId)) return false;
  const day = Date.parse(row.action?.time ?? '');
  if (!Number.isFinite(day) || day > issuedAt || day < issuedAt - CF_WINDOW_DAYS * DAY_MS) return false;
  try {
    const text = JSON.stringify(row);
    return rowPieces(text).every(p => p.kind === 'R' || p.end - p.start <= 4096);
  } catch { return false; }
}

const pair = row => `${cloudflareCatalogOperation(row.resource?.product, row.resource?.type, row.action?.type)?.group}|${row.action.time.slice(0, 10)}`;

export function selectCloudflareWindows(rows, userId, now = Date.now()) {
  const sorted = [...rows].filter(r => Number.isFinite(Date.parse(r?.action?.time ?? ''))).sort((a, b) => Date.parse(b.action.time) - Date.parse(a.action.time));
  const blocks = [];
  for (let at = 0; at < sorted.length; at += CF_PAGE_LIMIT_MAX) {
    const block = sorted.slice(at, at + CF_PAGE_LIMIT_MAX);
    const pairs = new Set(block.filter(r => provableRow(r, userId, now)).map(pair));
    if (pairs.size) blocks.push({ block, pairs, at });
  }
  // Greedy: the block adding the most new pairs, until the session budget is used.
  const chosen = [], seen = new Set();
  while (chosen.length < CF_PAGE_STEPS.length) {
    let best = null, bestGain = 0;
    for (const b of blocks) {
      if (chosen.includes(b)) continue;
      const gain = [...b.pairs].filter(p => !seen.has(p)).length;
      if (gain > bestGain) { best = b; bestGain = gain; }
    }
    if (!best) break;
    chosen.push(best); best.pairs.forEach(p => seen.add(p));
  }
  return chosen.sort((a, b) => a.at - b.at).map(({ block }) => {
    const newest = Date.parse(block[0].action.time), oldest = Date.parse(block.at(-1).action.time);
    // since/before are exclusive bounds: one millisecond around the block's rows.
    return { since: iso(oldest - 1), before: iso(newest + 1), limit: CF_PAGE_LIMIT_MAX };
  });
}

export function selectCloudflareRows(rows, mappable, userId, issuedAt) {
  const candidates = rows.map((row, index) => ({ row, index })).filter(({ row, index }) => mappable(index) && provableRow(row, userId, issuedAt));
  const seen = new Set(), first = [], rest = [];
  for (const c of candidates) { const p = pair(c.row); (seen.has(p) ? rest : first).push(c); seen.add(p); }
  const picked = new Set([...first, ...rest].slice(0, CF_PAGE_ROW_CAP).map(c => c.index));
  // Every row before the last proven one is covered, a row left out as one hidden value: stop at the first row that
  // is neither picked nor hideable (not in one chunk, or wider than the widest piece circuit).
  const kept = [];
  for (let index = 0; index < rows.length; index++) {
    if (picked.has(index)) kept.push(index);
    else if (!mappable(index) || JSON.stringify(rows[index]).length > CF_SKIPPED_ROW_MAX) break;
  }
  return kept;
}
