/**
 * Proven sessions of one AWS check, in order: the IAM identity, then either one CloudTrail event per selected skill
 * area (E0, E1, ...: each fetches exactly one event by EventId) or up to AWS_MAX_PAGE_SESSIONS page sessions (P0, P1,
 * ...: each fetches one LookupEvents page of the user by Username and a StartTime/EndTime window, and proves several
 * of its rows). A run uses one kind only.
 *
 * AWS_MAX_EVENT_SESSIONS caps the event sessions per run: each one adds proofs, so it follows measured proving
 * speed. AWS_EVENT_STEP_LIMIT is the ceiling of the step names (E0..E7) that the backend ledger accepts.
 */
export const AWS_EVENT_STEP_LIMIT = 8;
export const AWS_MAX_EVENT_SESSIONS = 4;
export const AWS_MAX_PAGE_SESSIONS = 5;

export function awsSessionSteps(cap) {
  if (!Number.isInteger(cap) || cap < 1 || cap > AWS_EVENT_STEP_LIMIT) throw new Error('AWS_SESSION_CAP_INVALID');
  return Object.freeze(['identity', ...Array.from({ length: cap }, (_, index) => `E${index}`)]);
}

/** Every accepted step of this build, identity first. */
export const AWS_SESSION_STEPS = awsSessionSteps(AWS_MAX_EVENT_SESSIONS);
export const AWS_EVENT_STEPS = Object.freeze(AWS_SESSION_STEPS.slice(1));
export const AWS_PAGE_STEPS = Object.freeze(Array.from({ length: AWS_MAX_PAGE_SESSIONS }, (_, index) => `P${index}`));
/** Steps of a page run, identity first. */
export const AWS_PAGE_SESSION_STEPS = Object.freeze(['identity', ...AWS_PAGE_STEPS]);

/** Steps of a collected run, identity first: a page run's second request asks LookupEvents by Username. */
export function awsCollectedSteps(requests) {
  let page = false;
  try { page = JSON.parse(requests[1].body).LookupAttributes[0].AttributeKey === 'Username'; } catch { /* identity only, or events */ }
  return page ? AWS_PAGE_SESSION_STEPS : AWS_SESSION_STEPS;
}
