import type { PrivateProofModule, GcpPrivateSession, GcpPrivateRevealPlan } from '../offscreen/gcpPrivateWitness';

export interface AwsPrivateAttempt {
  proofId: string; pluginSha256: string; nonceMac: string;
  identityService: 'iam'; region: 'us-east-1'; issuedAt: number; expiresAt: number;
  /** Catalog skill groups the job names (server attempt state): a ranking weight for the local selection only. */
  jobGroups?: string[];
}
export interface AwsPrivateResult {
  kind: 'AWS_PRIVATE_RESULT'; version: 1; sessionIds: string[];
  proofs: Array<{ circuitId: string; proof: string; publicInputs: string[] }>;
}
export interface AwsPrivateModule extends PrivateProofModule {
  readonly fastCheck?: boolean;
  clear(): void;
  getRevealPlan(session: Readonly<GcpPrivateSession>, transcripts: { sent: Uint8Array; recv: Uint8Array }): GcpPrivateRevealPlan;
  /** The event ids each page session proves (P0..), from the local selection; before the first page session. */
  selectPages(rows: Record<string, string[]>): void;
}
export function validateAwsAttempt(value: unknown, now?: number): void;
/** identity, then E0.. up to the per-run event-session cap. */
export const AWS_SESSION_STEPS: readonly string[];
/** Page run steps after identity: P0.. up to the page-session cap. */
export const AWS_PAGE_STEPS: readonly string[];
/** The host a step must reach: IAM, CloudTrail us-east-1, or for a page step the allowed CloudTrail host named. */
export function awsSessionHost(step: string, serverName: string): string;
/** Steps of a collected run, identity first (page runs ask LookupEvents by Username). */
export function awsCollectedSteps(requests: readonly { body?: string }[]): readonly string[];
export interface AwsCredentials { accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: string }
export interface AwsCapture { credentials: AwsCredentials; accountId?: string }
export interface AwsSignedRequest { url: string; method: string; headers: Record<string, string>; body: string }
export function awsPrivateCredentials(value: unknown, now?: number): AwsCredentials;
export function awsConsoleSession(value: unknown, now?: number): { url: string; headers: Record<string, string>; accountId?: string };
export function readAwsPrivateResponse(url: string, options: RequestInit, deps?: { fetchAws?: typeof fetch; signal?: AbortSignal }): Promise<string>;
export function createAwsLocalSession(options: { attempt: AwsPrivateAttempt; identityOnly?: boolean; pages?: boolean }): {
  prepare(capture: AwsCapture): Promise<AwsSignedRequest[]>; clear(): void;
  /** After prepare() of a page run: the event ids each page session proves, else undefined. */
  pageRows(): Record<string, string[]> | undefined;
};
export function sanitizeAwsPrivateResult(value: unknown): AwsPrivateResult;
export function createAwsPrivateModule(options: {
  fastSource?: { userIdHash: string; length: number }; linkSecret?: Uint8Array;
  attempt: AwsPrivateAttempt; workerUrl: string; onProgress?: (value: { completedProofs: number }) => void;
}): AwsPrivateModule;
