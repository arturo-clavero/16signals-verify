/**
 * Local, unproven discovery of an IAM user's CloudTrail write activity over the 90 days before `end`.
 * Nothing found here is sent to 16signals or claimed: it only chooses which events the proven page sessions fetch.
 *
 * LookupEvents allows one lookup attribute (Username here), 50 rows per page, newest first, 2 requests/s per account
 * and Region. One newest-first query over 90 days stops at the busiest recent days, so the window is cut into time
 * slices and each slice is read newest first. Pages are handed out round robin over the slices that still have a
 * NextToken: a slice that runs out early leaves its share to the busy ones.
 *
 * Besides the candidate events, discovery returns the time of every row it saw (reads and failures too) and the time
 * ranges in which it saw every row. A proven session re-fetches one page by StartTime/EndTime, so its window must
 * lie in such a range for its row count to be known.
 */
import { AWS_REGION, AWS_REGIONS, AWS_EVENT_ID, awsRegionHolds } from './request.mjs';
import { awsCatalogOperation } from './skill-groups.mjs';
import { awsToolClass, awsToolName } from './tool-class.mjs';
import { AWS_EVENT_BATCH_CIRCUITS } from './event-batch.mjs';

const encoder = new TextEncoder();
const USER_AGENT_KEY = ',\\"userAgent\\":', RECIPIENT_KEY = ',\\"recipientAccountId\\":';
/** Wire bytes of the row's committed body (userAgent value up to recipientAccountId): it decides the batch circuit. */
export function awsRowBodyBytes(cloudTrailEvent) {
  const wire = JSON.stringify(cloudTrailEvent), from = wire.indexOf(USER_AGENT_KEY), to = wire.indexOf(RECIPIENT_KEY, from);
  return from < 0 || to < 0 ? Infinity : encoder.encode(wire.slice(from + USER_AGENT_KEY.length, to)).length;
}

const DAY = 86400;
/** Slices in days before `end`, newest first. */
export const AWS_DISCOVERY_SLICES = Object.freeze([[0, 3], [3, 7], [7, 14], [14, 30], [30, 60], [60, 90]].map(Object.freeze));
/**
 * Budget: stop starting requests after AWS_DISCOVERY_MS, and never read more than AWS_DISCOVERY_PAGES pages. A 50-row page
 * takes about 1.2 s end to end (measured, us-east-1), more than the 650 ms request interval, so time binds first.
 */
export const AWS_DISCOVERY_MS = 50000;
export const AWS_DISCOVERY_PAGES = 80;
export const AWS_PAGE_ROWS = 50;
/** Regions probed at the same time (each still paced on its own lane). */
export const AWS_DISCOVERY_REGION_CONCURRENCY = 6;

const fail = what => { throw new Error(`AWS_DISCOVERY_INVALID:${what}`); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

/** The slices as [start, end] in epoch seconds, newest first. AWS includes both bounds, so neighbours share one second. */
export function awsDiscoverySlices(end) {
  if (!Number.isSafeInteger(end) || end <= 90 * DAY) fail('end');
  return AWS_DISCOVERY_SLICES.map(([from, to]) => ({ start: end - to * DAY, end: end - from * DAY }));
}

/**
 * The candidate an event row gives, or null. Only successful management writes of a catalog operation, made by exactly
 * the proven IAM user (no service acting for it), in `region`, with a provable userAgent, inside [start, end]. Global
 * services (IAM, STS, CloudFront, Route 53, Organizations) count in us-east-1 only, where CloudTrail records them.
 */
export function awsDiscoveryCandidate(row, event, { identity, start, end, region = AWS_REGION }) {
  const actor = event?.userIdentity;
  if (!event || typeof event !== 'object' || !AWS_EVENT_ID.test(row.EventId) || event.eventID !== row.EventId ||
      event.readOnly !== false || event.managementEvent !== true || event.errorCode !== undefined ||
      event.errorMessage !== undefined || event.awsRegion !== region || actor?.type !== 'IAMUser' ||
      actor.principalId !== identity.principalId || actor.arn !== identity.arn || actor.accountId !== identity.accountId ||
      actor.invokedBy !== undefined || actor.inScopeOf !== undefined || event.recipientAccountId !== identity.accountId ||
      typeof event.userAgent !== 'string' || /["\\]/.test(event.userAgent)) return null;
  const op = awsCatalogOperation(event.eventSource, event.eventName), ms = Date.parse(event.eventTime);
  if (!op || !awsRegionHolds(region, op.eventSource) || !Number.isFinite(ms) || ms !== row.EventTime * 1000 ||
      row.EventTime < start || row.EventTime > end) return null;
  // Rows longer than the widest batch circuit cannot be proven.
  const body = awsRowBodyBytes(row.CloudTrailEvent);
  if (body > AWS_EVENT_BATCH_CIRCUITS.at(-1).bodyBytes) return null;
  return Object.freeze({ eventId: row.EventId, region, time: row.EventTime, day: Math.floor(row.EventTime / DAY),
    eventSource: op.eventSource, eventName: op.eventName, group: op.group, tier: op.tier, auto: op.auto,
    tool: awsToolName(awsToolClass(JSON.stringify(event.userAgent))), body });
}

const lowerBound = (times, value) => {
  let lo = 0, hi = times.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (times[mid] < value) lo = mid + 1; else hi = mid; }
  return lo;
};

/**
 * How many rows a LookupEvents page for [start, end] holds, or null when that is unknown (outside the ranges in
 * which discovery saw every row).
 */
export function awsWindowRows({ times, coverage }, start, end) {
  if (!(start <= end) || !coverage.some(range => range.start <= start && end <= range.end)) return null;
  return lowerBound(times, end + 1) - lowerBound(times, start);
}

/**
 * Row count of a page window in `region`. `discovery` is a discoverAwsRegions result, or one Region's
 * discoverAwsActivity result (no `regions` field). Null when unknown.
 */
export function awsRegionWindowRows(discovery, region = AWS_REGION, start, end) {
  const own = discovery.regions ? discovery.regions[region] : (discovery.region ?? AWS_REGION) === region ? discovery : undefined;
  return own ? awsWindowRows(own, start, end) : null;
}

/** A window that surely contains the event: AWS bounds are inclusive and times are whole seconds. */
export const awsEventWindow = time => ({ start: time - 1, end: time + 1 });

/**
 * Reads pages of one Region until `maxPages` or `timeMs` (`read` signs, paces and fetches one LookupEvents request and
 * returns the body text, or null when a later read failed in transit: discovery then ends with the pages read so far) and returns { candidates (newest first), times (ascending), coverage, requests, slices }.
 * `probe`: the body of an already read first page over the whole 90 days; when it has no NextToken it holds every row
 * and no slice is read. Candidates that cannot be placed in any page window (unknown row count or more than 50 rows
 * around them) are dropped here.
 */
export async function discoverAwsActivity({ read, identity, end, region = AWS_REGION, maxPages = AWS_DISCOVERY_PAGES,
  timeMs = AWS_DISCOVERY_MS, now = Date.now, probe }) {
  if (typeof read !== 'function' || !Number.isSafeInteger(maxPages) || maxPages < (probe === undefined ? 1 : 0) || !(timeMs > 0) ||
      typeof identity?.arn !== 'string' || !identity.arn.includes('/') || !AWS_REGIONS.includes(region)) fail('input');
  const userName = identity.arn.slice(identity.arn.lastIndexOf('/') + 1);
  const window = { start: end - 90 * DAY, end };
  const slices = awsDiscoverySlices(end).map(range => ({ ...range, pages: 0, rows: 0, oldest: undefined, nextToken: undefined, done: false }));
  const seen = new Map(), candidates = new Map(), tokens = new Set(), extra = [];
  const started = now(), more = () => !stopped && requests < maxPages && now() - started < timeMs;
  let requests = 0, stopped = false;
  /** Takes one page of [range.start, range.end]; returns its NextToken (undefined on the last page) and oldest row. */
  const ingest = (text, range) => {
    let page, oldest;
    try { page = JSON.parse(text); } catch { fail('page'); }
    if (!exact(page, ['Events', ...(page?.NextToken === undefined ? [] : ['NextToken'])]) || !Array.isArray(page.Events) ||
        page.Events.length > AWS_PAGE_ROWS) fail('page');
    for (const row of page.Events) {
      if (!row || typeof row.EventId !== 'string' || !Number.isSafeInteger(row.EventTime) ||
          row.EventTime < range.start || row.EventTime > range.end || typeof row.CloudTrailEvent !== 'string') fail('row');
      oldest = Math.min(oldest ?? Infinity, row.EventTime);
      if (seen.has(row.EventId)) continue;
      seen.set(row.EventId, row.EventTime);
      let event;
      try { event = JSON.parse(row.CloudTrailEvent); } catch { continue; }
      const candidate = awsDiscoveryCandidate(row, event, { identity, ...window, region });
      if (candidate) candidates.set(candidate.eventId, candidate);
    }
    const next = page.NextToken;
    if (next !== undefined && (typeof next !== 'string' || !next || next.length > 8192 || tokens.has(next))) fail('token');
    if (next) tokens.add(next);
    return { next, oldest, rows: page.Events.length };
  };
  if (probe !== undefined) {
    const { next, oldest } = ingest(probe, window);
    if (!next) for (const slice of slices) slice.done = true;
    else if (oldest < end) extra.push({ start: oldest + 1, end });
  }
  while (more()) {
    const active = slices.filter(slice => !slice.done);
    if (!active.length) break;
    for (const slice of active) {
      if (!more()) break;
      requests++;
      const text = await read({ kind: 'discovery', region, userName, start: slice.start, end: slice.end,
        ...(slice.nextToken ? { nextToken: slice.nextToken } : {}) });
      if (text === null) {
        if (requests === 1 && probe === undefined) fail('read');
        stopped = true; break;
      }
      const { next, oldest, rows } = ingest(text, slice);
      slice.pages++;
      slice.rows += rows;
      slice.oldest = Math.min(slice.oldest ?? Infinity, oldest ?? Infinity);
      slice.nextToken = next;
      slice.done = !next;
    }
  }
  // Every row of a finished slice was seen; for an unfinished one, every row newer than its oldest seen second (rows of
  // that second may continue on the next page).
  const ranges = slices.flatMap(slice => slice.done ? [{ start: slice.start, end: slice.end }]
    : slice.oldest !== undefined && slice.oldest < slice.end ? [{ start: slice.oldest + 1, end: slice.end }] : [])
    .concat(extra).sort((a, b) => a.start - b.start);
  const coverage = [];
  for (const range of ranges) {
    const last = coverage.at(-1);
    if (last && range.start <= last.end + 1) last.end = Math.max(last.end, range.end); else coverage.push({ ...range });
  }
  const times = [...seen.values()].sort((a, b) => a - b);
  const placeable = candidate => {
    const { start, end: stop } = awsEventWindow(candidate.time), rows = awsWindowRows({ times, coverage }, start, stop);
    return rows !== null && rows <= AWS_PAGE_ROWS;
  };
  return {
    candidates: [...candidates.values()].filter(placeable).sort((a, b) => b.time - a.time || (a.eventId < b.eventId ? -1 : 1)),
    region, times, coverage, requests, found: candidates.size, stoppedEarly: stopped,
    slices: slices.map(({ start, end: stop, pages, rows, done }) => ({ start, end: stop, pages, rows, complete: done })),
  };
}

/**
 * Discovery over every enabled Region. LookupEvents is regional (the 2 requests/s limit is per account and Region), so
 * Regions are read in parallel (a few at a time, AWS_DISCOVERY_REGION_CONCURRENCY). us-east-1 (home of the global services) is read in slices from the start. Every other
 * Region gets a probe: one newest-first page over the whole 90 days. A Region whose probe holds every row needs nothing
 * more; one with more rows is read in slices only when the probe found candidate writes. A Region whose probe fails is
 * not enabled for this account (opt-in Regions) or not readable and is skipped; a failure in us-east-1 fails discovery
 * as before. `read(options)` gets the Region in `options.region`. Everything shares one time budget.
 *
 * Returns { candidates (every Region, newest first), regions: { <region>: discoverAwsActivity result }, requests,
 * probe: { regions, enabled, sliced } } (counts and Region names only).
 */
export async function discoverAwsRegions({ read, identity, end, regions = AWS_REGIONS, maxPages = AWS_DISCOVERY_PAGES,
  timeMs = AWS_DISCOVERY_MS, now = Date.now }) {
  if (typeof read !== 'function' || !Array.isArray(regions) || !regions.includes(AWS_REGION) ||
      new Set(regions).size !== regions.length || regions.some(region => !AWS_REGIONS.includes(region)) ||
      typeof identity?.arn !== 'string' || !identity.arn.includes('/')) fail('input');
  const userName = identity.arn.slice(identity.arn.lastIndexOf('/') + 1), started = now(), base = { read, identity, end, now };
  const home = discoverAwsActivity({ ...base, region: AWS_REGION, maxPages, timeMs });
  // Awaited after the other Regions; a failure here still fails discovery, without an unhandled rejection meanwhile.
  home.catch(() => {});
  const others = regions.filter(region => region !== AWS_REGION);
  const sliced = [AWS_REGION], unread = [];
  const discoverAway = async region => {
    let probe;
    try {
      probe = await read({ kind: 'discovery', region, userName, start: end - 90 * DAY, end });
    } catch {
      // Refused (a Region not enabled for this account, or not readable): skipped as before.
      return undefined;
    }
    // Still failing in transit after the read's own retries: the Region is enabled but unread this run, and says so.
    if (probe === null) { unread.push(region); return undefined; }
    const first = await discoverAwsActivity({ ...base, region, probe, maxPages: 0 });
    const left = timeMs - (now() - started);
    if (first.slices[0].complete || !first.found || left <= 0) return first;
    sliced.push(region);
    return discoverAwsActivity({ ...base, region, probe, maxPages, timeMs: left });
  };
  // A few Regions at a time rather than every probe at once: a burst of dozens of requests is what times out on a busy
  // machine or a slow link. Each Region keeps its own 2 requests/s lane.
  const away = new Array(others.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(AWS_DISCOVERY_REGION_CONCURRENCY, others.length) }, async () => {
    while (next < others.length) { const index = next++; away[index] = await discoverAway(others[index]); }
  }));
  const homeResult = await home;
  const results = [homeResult, ...away.filter(Boolean)];
  return {
    candidates: results.flatMap(result => result.candidates).sort((a, b) => b.time - a.time || (a.eventId < b.eventId ? -1 : 1)),
    regions: Object.fromEntries(results.map(result => [result.region, result])),
    requests: others.length + results.reduce((sum, result) => sum + result.requests, 0),
    probe: { regions: regions.length, enabled: results.length, sliced: regions.filter(region => sliced.includes(region)),
      unread: regions.filter(region => unread.includes(region)), homeComplete: homeResult.stoppedEarly !== true },
  };
}
