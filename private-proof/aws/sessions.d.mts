export const AWS_EVENT_STEP_LIMIT: number;
export const AWS_MAX_EVENT_SESSIONS: number;
export function awsSessionSteps(cap: number): readonly string[];
export const AWS_SESSION_STEPS: readonly string[];
export const AWS_EVENT_STEPS: readonly string[];
export const AWS_MAX_PAGE_SESSIONS: number;
export const AWS_PAGE_STEPS: readonly string[];
export const AWS_PAGE_SESSION_STEPS: readonly string[];
export function awsCollectedSteps(requests: ReadonlyArray<{ body?: string } | null>): readonly string[];
