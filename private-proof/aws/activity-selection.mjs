/**
 * Chooses which discovered events to prove (a budget of B rows) and packs them into page sessions.
 * Local and deterministic; every pick carries the reason it was taken.
 *
 * Levels per skill group (counted over proven events only):
 *   Observed   one event.
 *   Repeated   events on 2 distinct UTC days.
 *   Sustained  non-auto events on 3 distinct UTC days spanning at least 14 days, one of them intermediate or advanced.
 *              Ops usually run by CI or scripts (auto) never count toward Sustained.
 *   Advanced   marker: any advanced op.
 * The UTC day only decides levels; it is never part of what employers see.
 *
 * Ranking: each group gets a ladder of up to four events (first observation, 2nd day, 3rd day, first advanced op),
 * chosen so that the best level the group can reach is reached with the fewest events. A step is worth
 *   groupWeight x stepValue x tier x non-auto x tool novelty
 * groupWeight is 1.5 for groups the job names and 1 otherwise (a job that only says "AWS" names no group). The job's
 * groups come from its tags (`jobTags`) or, in a run, from the attempt (`jobGroups`: catalog group ids the server read
 * from the job); they only weigh the choice, never limit it, and an id this catalog does not know is ignored. Every
 * discovered group gets its first observation before any group gets depth, unless the budget is smaller than the number
 * of groups: then job groups first, then by value. After that the highest-valued next step wins until the budget is
 * spent or no step adds anything; unused budget is not spent. Ties between equal events prefer a body that fits the
 * five-row batch proof, then (with `discovery`) an event that shares a page window with an earlier pick.
 *
 * Regions: a page session reads one Region, so packing keeps Regions apart; levels and ranking ignore the Region (a
 * Lambda change in eu-west-1 is the same evidence as one in us-east-1). Events without `region` are us-east-1.
 */
import { AWS_SKILL_GROUPS } from './skill-groups.mjs';
import { awsRegionWindowRows, AWS_PAGE_ROWS } from './activity-discovery.mjs';
import { AWS_REGION } from './request.mjs';
import { AWS_EVENT_BATCH_CIRCUITS } from './event-batch.mjs';

export const AWS_STEP_VALUES = Object.freeze({ observed: 1, repeated: 0.6, sustained: 0.5, advanced: 0.3 });
export const AWS_TIER_FACTORS = Object.freeze({ basic: 1, intermediate: 1.15, advanced: 1.3 });
export const AWS_JOB_WEIGHT = 1.5;
export const AWS_AUTO_FACTOR = 0.8;
export const AWS_NEW_TOOL_FACTOR = 1.1;
export const AWS_SUSTAINED_SPAN_DAYS = 14;
// Tie-break only: infrastructure as code and CLI over hand-driven clients.
const TOOL_ORDER = ['terraform', 'cli', 'sdk-other', 'console'];
const STEPS = ['observed', 'repeated', 'sustained'];

const fail = what => { throw new Error(`AWS_SELECTION_INVALID:${what}`); };
const groupOrder = new Map(AWS_SKILL_GROUPS.map((group, index) => [group.id, index]));
const label = id => AWS_SKILL_GROUPS.find(group => group.id === id).label;
const score = event => AWS_TIER_FACTORS[event.tier] * (event.auto ? AWS_AUTO_FACTOR : 1);
const toolRank = event => { const index = TOOL_ORDER.indexOf(event.tool); return index < 0 ? TOOL_ORDER.length : index; };
const byId = (a, b) => (a.eventId < b.eventId ? -1 : a.eventId > b.eventId ? 1 : 0);
// Rows whose body fits the five-row batch circuit cost less to prove than those that need the three-row one.
const wide = event => Number((event.body ?? 0) > AWS_EVENT_BATCH_CIRCUITS[0].bodyBytes);
/** Better single event first: score, then a body that fits the five-row batch proof, then IaC/CLI, then newest, then id. */
const betterEvent = (a, b) => score(b) - score(a) || wide(a) - wide(b) || toolRank(a) - toolRank(b) || b.time - a.time || byId(a, b);

/** Normalised job tags (lowercase, spaces and underscores to hyphens) to the skill groups they name. */
export function awsJobGroups(jobTags = []) {
  if (!Array.isArray(jobTags)) fail('jobTags');
  const tags = new Set(jobTags.filter(tag => typeof tag === 'string').map(tag => tag.trim().toLowerCase().replace(/[\s_]+/g, '-')));
  return new Set(AWS_SKILL_GROUPS.filter(group => group.jobTags.some(tag => tags.has(tag))).map(group => group.id));
}

const jobSet = (jobTags, jobGroups) => {
  if (!Array.isArray(jobGroups)) fail('jobGroups');
  const job = awsJobGroups(jobTags);
  for (const id of jobGroups) if (groupOrder.has(id)) job.add(id);
  return job;
};

/** The level a set of proven events of one group supports. */
export function awsGroupLevel(events) {
  const days = new Set(events.map(e => e.day)), manual = events.filter(e => !e.auto), manualDays = [...new Set(manual.map(e => e.day))];
  const level = !events.length ? null
    : manualDays.length >= 3 && Math.max(...manualDays) - Math.min(...manualDays) >= AWS_SUSTAINED_SPAN_DAYS &&
      manual.some(e => e.tier !== 'basic') ? 'sustained'
    : days.size >= 2 ? 'repeated' : 'observed';
  return { level, advanced: events.some(e => e.tier === 'advanced') };
}

const span = events => Math.max(...events.map(e => e.day)) - Math.min(...events.map(e => e.day));
const setScore = events => events.reduce((sum, e) => sum + score(e), 0) + 0.1 * new Set(events.map(e => e.tool).filter(Boolean)).size +
  (events.some(e => e.tier === 'advanced') ? AWS_STEP_VALUES.advanced : 0) + 0.05 * new Set(events.map(e => e.eventName)).size;
const betterSet = (a, b) => setScore(b) - setScore(a) || span(b) - span(a) ||
  Math.max(...b.map(e => e.time)) - Math.max(...a.map(e => e.time)) || a.map(e => e.eventId).join().localeCompare(b.map(e => e.eventId).join());
const best = sets => sets.reduce((a, b) => (betterSet(a, b) <= 0 ? a : b));

/** Fewest events reaching the group's best level, best first; plus its best advanced event when the set has none. */
function ladder(events) {
  const byDay = new Map();
  for (const e of [...events].sort(betterEvent)) byDay.set(e.day, [...(byDay.get(e.day) ?? []), e]);
  const days = [...byDay.keys()].sort((a, b) => a - b);
  let chosen;
  // Sustained: per day the best non-auto event, or its best non-auto intermediate/advanced one when the trio needs it.
  const manual = days.map(day => ({ day, top: byDay.get(day).find(e => !e.auto), deep: byDay.get(day).find(e => !e.auto && e.tier !== 'basic') }))
    .filter(entry => entry.top);
  const trios = [];
  for (let i = 0; i < manual.length; i++) for (let j = i + 1; j < manual.length; j++) for (let k = j + 1; k < manual.length; k++) {
    if (manual[k].day - manual[i].day < AWS_SUSTAINED_SPAN_DAYS) continue;
    const trio = [manual[i], manual[j], manual[k]];
    if (trio.some(entry => entry.top.tier !== 'basic')) trios.push(trio.map(entry => entry.top));
    else for (const swap of trio.filter(entry => entry.deep)) trios.push(trio.map(entry => entry === swap ? entry.deep : entry.top));
  }
  if (trios.length) chosen = best(trios);
  else if (days.length >= 2) {
    const pairs = [];
    for (let i = 0; i < days.length; i++) for (let j = i + 1; j < days.length; j++) pairs.push([byDay.get(days[i])[0], byDay.get(days[j])[0]]);
    chosen = best(pairs);
  } else chosen = [byDay.get(days[0])[0]];
  chosen = [...chosen].sort(betterEvent);
  const steps = chosen.map((event, index) => ({ event, step: STEPS[index] }));
  if (!chosen.some(e => e.tier === 'advanced')) {
    const advanced = [...events].filter(e => e.tier === 'advanced').sort(betterEvent)[0];
    if (advanced) steps.push({ event: advanced, step: 'advanced' });
  }
  return steps;
}

/**
 * Tie-break after ranking: a pick that shares no page window with an earlier pick is swapped for an equivalent event
 * (same group, day, operation tier, auto flag, tool and batch circuit, so the same value and levels) that does, the
 * nearest in time. Fewer windows mean fewer page sessions.
 */
const regionOf = event => event.region ?? AWS_REGION;
function packTogether(picks, candidates, discovery) {
  const packs = (a, b) => {
    if (regionOf(a) !== regionOf(b)) return false;
    const rows = awsRegionWindowRows(discovery, regionOf(a), Math.min(a.time, b.time), Math.max(a.time, b.time));
    return rows !== null && rows <= AWS_PAGE_ROWS;
  };
  const taken = new Set(picks.map(pick => pick.eventId));
  picks.forEach((pick, index) => {
    const earlier = picks.slice(0, index).map(other => other.event);
    if (!earlier.length || earlier.some(other => packs(other, pick.event))) return;
    const same = event => ['group', 'day', 'tier', 'auto', 'tool'].every(name => event[name] === pick.event[name]) && wide(event) === wide(pick.event);
    const distance = event => Math.min(...earlier.map(other => Math.abs(other.time - event.time)));
    const swap = candidates.filter(event => !taken.has(event.eventId) && same(event) && earlier.some(other => packs(other, event)))
      .sort((a, b) => distance(a) - distance(b) || byId(a, b))[0];
    if (!swap) return;
    taken.delete(pick.eventId); taken.add(swap.eventId);
    picks[index] = { ...pick, eventId: swap.eventId, event: swap };
  });
}

/**
 * Picks up to `budget` events from discovery candidates. Returns { picks, groups }: picks in the order taken, each with
 * its step, value and reason; groups with what was found and the level the picks reach.
 */
export function rankAwsActivity(candidates, { budget, jobTags = [], jobGroups = [], discovery }) {
  if (!Array.isArray(candidates) || !Number.isSafeInteger(budget) || budget < 0) fail('input');
  const job = jobSet(jobTags, jobGroups), found = new Map();
  for (const e of candidates) {
    if (!groupOrder.has(e?.group) || !(e.tier in AWS_TIER_FACTORS)) fail('candidate');
    found.set(e.group, [...(found.get(e.group) ?? []), e]);
  }
  const ladders = [...found.keys()].sort((a, b) => groupOrder.get(a) - groupOrder.get(b)).map(group => {
    const weight = job.has(group) ? AWS_JOB_WEIGHT : 1, tools = new Set();
    let hasAdvanced = false;
    const steps = ladder(found.get(group)).map(({ event, step }, index) => {
      const firstAdvanced = event.tier === 'advanced' && !hasAdvanced, newTool = index > 0 && event.tool && !tools.has(event.tool);
      hasAdvanced ||= event.tier === 'advanced';
      if (event.tool) tools.add(event.tool);
      const stepValue = AWS_STEP_VALUES[step] + (firstAdvanced && step !== 'advanced' ? AWS_STEP_VALUES.advanced : 0);
      const value = weight * stepValue * score(event) * (newTool ? AWS_NEW_TOOL_FACTOR : 1);
      const reason = [`${step === 'observed' ? 'first observation' : step === 'repeated' ? 'second distinct day'
        : step === 'sustained' ? 'third distinct day over 14+ days' : 'first advanced operation'} of ${label(group)}`,
      job.has(group) ? 'named by the job' : null, `${event.tier} operation${event.auto ? ', usually automated' : ''}`,
      firstAdvanced && step !== 'advanced' ? 'first advanced operation' : null, newTool ? `new tool (${event.tool})` : null]
        .filter(Boolean).join('; ');
      return { eventId: event.eventId, group, step, value: Math.round(value * 1000) / 1000, reason, event };
    });
    return { group, job: job.has(group), steps, next: 0 };
  });
  const picks = [], take = entry => { picks.push(entry.steps[entry.next]); entry.next++; };
  const order = (a, b) => b.steps[b.next].value - a.steps[a.next].value || groupOrder.get(a.group) - groupOrder.get(b.group);
  // Breadth floor: first observations, job groups first when the budget cannot cover every group.
  for (const entry of [...ladders].sort((a, b) => Number(b.job) - Number(a.job) || order(a, b)).slice(0, budget)) take(entry);
  while (picks.length < budget) {
    const open = ladders.filter(entry => entry.next > 0 && entry.next < entry.steps.length).sort(order);
    if (!open.length) break;
    take(open[0]);
  }
  if (discovery) packTogether(picks, candidates, discovery);
  const groups = ladders.map(({ group, job: named, steps, next }) => {
    const events = found.get(group), proven = steps.slice(0, next).map(step => step.event);
    return { group, label: label(group), job: named, days: new Set(events.map(e => e.day)).size, events: events.length,
      operations: new Set(events.map(e => e.eventName)).size, tools: [...new Set(events.map(e => e.tool).filter(Boolean))].sort(),
      reachable: awsGroupLevel(events), proven: awsGroupLevel(proven), picked: next };
  });
  return { picks: picks.map(({ event, ...pick }) => ({ ...pick, region: regionOf(event), time: event.time, day: event.day })), groups };
}

/**
 * Packs picks into page sessions: each a StartTime/EndTime window of one Region whose LookupEvents page holds at most
 * 50 rows (all of the user's rows in it, known from discovery) and at most `rowCap` picks. Per Region, windows follow
 * time order, which gives the fewest sessions. Sessions holding job-group evidence come first, so a deadline cut keeps
 * the most useful evidence; `maxSessions` is the budget of the whole run (all Regions), the rest is returned deferred.
 */
export function packAwsSessions(picks, discovery, { rowCap, jobTags = [], jobGroups = [], maxSessions = Infinity }) {
  if (!Array.isArray(picks) || !Number.isSafeInteger(rowCap) || rowCap < 1) fail('input');
  const job = jobSet(jobTags, jobGroups), sessions = [], unplaced = [];
  const regions = [...new Set(picks.map(regionOf))].sort();
  for (const region of regions) {
    const sorted = picks.filter(pick => regionOf(pick) === region).sort((a, b) => a.time - b.time || byId(a, b));
    // AWS bounds are inclusive and times whole seconds: [first, last] holds every row of those seconds. Windows never
    // share a second, so no row is in two sessions (the verifier requires disjoint windows per Region).
    const fits = group => {
      const start = group[0].time, end = group.at(-1).time, rows = awsRegionWindowRows(discovery, region, start, end);
      return group.length <= rowCap && rows !== null && rows <= AWS_PAGE_ROWS ? { region, start, end, rows } : null;
    };
    let current = [];
    const close = () => { if (current.length) sessions.push({ ...fits(current), picks: current }); current = []; };
    for (const pick of sorted) {
      if (fits([...current, pick])) { current.push(pick); continue; }
      if (current.length && current.at(-1).time === pick.time) { unplaced.push(pick); continue; }
      close();
      if (fits([pick])) current = [pick]; else unplaced.push(pick);
    }
    close();
  }
  const worth = session => session.picks.reduce((sum, pick) => sum + pick.value, 0);
  const jobWorth = session => session.picks.reduce((sum, pick) => sum + (job.has(pick.group) ? pick.value : 0), 0);
  sessions.sort((a, b) => jobWorth(b) - jobWorth(a) || worth(b) - worth(a) || b.start - a.start || (a.region < b.region ? -1 : 1));
  const shaped = sessions.map(({ region, start, end, rows, picks: held }) => ({ region, start, end, rows, eventIds: held.map(pick => pick.eventId),
    groups: [...new Set(held.map(pick => pick.group))] }));
  return { sessions: shaped.slice(0, maxSessions), deferred: shaped.slice(maxSessions), unplaced: unplaced.map(pick => pick.eventId) };
}

/**
 * What the candidate sees before proving (local only, never sent): groups found, on how many days, and the level this
 * run is set to prove for each. Counts only, no dates.
 */
export function awsDiscoveryPreview(discovery, ranking, packing) {
  const sessionIds = new Set(packing.sessions.flatMap(session => session.eventIds));
  const proven = ranking.picks.filter(pick => sessionIds.has(pick.eventId));
  return {
    requests: discovery.requests,
    activeDays: new Set(discovery.candidates.map(e => e.day)).size,
    groups: ranking.groups.map(group => {
      const events = proven.filter(pick => pick.group === group.group).map(pick => discovery.candidates.find(e => e.eventId === pick.eventId));
      return { group: group.group, label: group.label, job: group.job, days: group.days, operations: group.operations, tools: group.tools,
        found: group.reachable.level, thisRun: awsGroupLevel(events).level, advanced: awsGroupLevel(events).advanced };
    }),
    provenEvents: proven.length,
    provenDays: new Set(proven.map(pick => pick.day)).size,
    sessions: packing.sessions.length,
  };
}
