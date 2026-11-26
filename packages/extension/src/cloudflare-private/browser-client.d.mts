import type { PrivateProofModule, GcpPrivateSession, GcpPrivateRevealPlan } from '../offscreen/gcpPrivateWitness';

export interface CloudflarePrivateAttempt { proofId: string; pluginSha256: string; nonceMac: string; issuedAt: number; expiresAt: number }
export interface CloudflarePrivateResult {
  kind: 'CLOUDFLARE_PRIVATE_RESULT'; version: 1; sessionIds: string[];
  proofs: Array<{ circuitId: string; proof: string; publicInputs: string[] }>;
}
export interface CloudflarePrivateModule extends PrivateProofModule {
  clear(): void;
  getRevealPlan(session: Readonly<GcpPrivateSession>, transcripts: { sent: Uint8Array; recv: Uint8Array }): GcpPrivateRevealPlan;
}
export interface CloudflareRequest { url: string; method: string; headers: Record<string, string> }
export function validateCloudflareAttempt(value: unknown, now?: number): void;
/** identity, P0, P1, P2 */
export const CF_RUN_STEPS: readonly string[];
export const CF_PAGE_STEPS: readonly string[];
export const CF_API_HOST: string;
export function createCloudflareLocalSession(options: { attempt: CloudflarePrivateAttempt; fetchCf?: typeof fetch }): {
  prepare(token: string): Promise<CloudflareRequest[]>; clear(): void;
};
export function sanitizeCloudflarePrivateResult(value: unknown): CloudflarePrivateResult;
export function createCloudflarePrivateModule(options: {
  attempt: CloudflarePrivateAttempt; workerUrl: string; onProgress?: (value: { completedProofs: number }) => void;
}): CloudflarePrivateModule;
