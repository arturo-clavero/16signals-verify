import { PrivateWitnessRun } from './gcpPrivateWitness';
import { CF_API_HOST, CF_PAGE_STEPS, CF_RUN_STEPS, createCloudflareLocalSession, sanitizeCloudflarePrivateResult, validateCloudflareAttempt,
  type CloudflarePrivateAttempt, type CloudflarePrivateModule, type CloudflareRequest } from '../cloudflare-private/browser-client.mjs';
import { cloudflareClientId, revokeCloudflareToken } from '../background/cloudflarePrivateAuth';

export const CF_PRIVATE_TIMEOUT_MS = 13 * 60 * 1000;
/** Run errors the candidate sees as they are (no value inside). */
export const CF_PASSED_ERRORS = ['CF_ACCOUNT_ACCESS_REQUIRED', 'CF_NO_ACTIVITY', 'CF_OAUTH_CANCELLED'];

/** One fixed diagnostic code per Cloudflare run stage for the offscreen console; never a value. */
export function cloudflareOffscreenStage(code: string): void {
  try { console.warn(`CF_OFF_${code}`); } catch { /* Diagnostics must not affect the run. */ }
}

const ATTEMPT_KEYS = ['proofId', 'pluginSha256', 'nonceMac', 'issuedAt', 'expiresAt'];
/** The plugin's `privateAttempt`: exactly the server attempt fields for this request and plugin. */
export function cloudflarePrivateAttemptParam(value: unknown, requestId: string | null | undefined, pluginSha256: string): CloudflarePrivateAttempt {
  const attempt = value as Record<string, unknown> | null;
  if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt) || Object.keys(attempt).length !== ATTEMPT_KEYS.length ||
      !ATTEMPT_KEYS.every(key => Object.hasOwn(attempt, key)) || attempt.proofId !== requestId || attempt.pluginSha256 !== pluginSha256) {
    throw new Error('CF_PRIVATE_PROVING_FAILED');
  }
  return attempt as unknown as CloudflarePrivateAttempt;
}

/** Compiled runner policy; page/plugin data cannot select the witness implementation. */
export class CloudflarePrivateWitnessRun extends PrivateWitnessRun {
  private deadline: ReturnType<typeof setTimeout>;
  private collection?: ReturnType<typeof createCloudflareLocalSession>;
  private token = '';
  private stopped = false;
  private failure = '';
  get passedError(): string { return this.failure; }
  private readonly collectionSteps: { step: string; host: string }[];
  private readonly attempt: CloudflarePrivateAttempt;
  /** Fast check (demo replay): the identity session only. */
  private readonly fastCheck: boolean;
  constructor(run: Record<string, string>, requestId: string | null, attempt: CloudflarePrivateAttempt, module: CloudflarePrivateModule) {
    validateCloudflareAttempt(attempt);
    if (run.proofId !== attempt.proofId || run.pluginSha256 !== attempt.pluginSha256 || typeof module.getRevealPlan !== 'function') {
      throw new Error('CF_PRIVATE_PROVING_FAILED');
    }
    // Filled by collect(): identity, then one page step per chosen window.
    const steps = [{ step: 'identity', host: CF_API_HOST }, { step: 'P0', host: CF_API_HOST }];
    super(run, requestId, module, {
      // The identity response is proven in part too (its id only): gaps allowed there as on page steps.
      method: 'CLOUDFLARE_ACCOUNT', nonceMac: attempt.nonceMac, proveTimeoutMs: CF_PRIVATE_TIMEOUT_MS, steps, pageSteps: ['identity', ...CF_PAGE_STEPS],
      finish(result, sessionIds) {
        const envelope = sanitizeCloudflarePrivateResult(result);
        if (envelope.sessionIds.length !== sessionIds.length || envelope.sessionIds.some((id, i) => id !== sessionIds[i])) throw new Error('CF_PRIVATE_PROVING_FAILED');
        return envelope;
      },
    });
    this.collectionSteps = steps;
    this.fastCheck = module.fastCheck === true;
    this.attempt = { ...attempt };
    this.deadline = setTimeout(() => this.clear(), Math.min(CF_PRIVATE_TIMEOUT_MS, attempt.expiresAt - Date.now()));
  }
  /** `signIn` asks the background for the OAuth token (Cloudflare's consent window). */
  async collect(signIn: () => Promise<{ token?: string; error?: string }>): Promise<CloudflareRequest[]> {
    if (this.stopped || this.collection) { cloudflareOffscreenStage('COLLECT_BUSY'); throw new Error('CF_PRIVATE_COLLECTION_FAILED'); }
    this.collection = createCloudflareLocalSession({ attempt: this.attempt, identityOnly: this.fastCheck });
    try {
      const reply = await signIn();
      if (typeof reply?.token !== 'string' || !reply.token) {
        cloudflareOffscreenStage('SIGN_IN_FAILED');
        throw new Error(reply?.error === 'CF_OAUTH_CANCELLED' ? 'CF_OAUTH_CANCELLED' : 'CF_PRIVATE_COLLECTION_FAILED');
      }
      this.token = reply.token;
      const requests = await this.collection.prepare(this.token);
      if (this.stopped || requests.length < (this.fastCheck ? 1 : 2) || requests.length > (this.fastCheck ? 1 : CF_RUN_STEPS.length)) { cloudflareOffscreenStage('COLLECT_COUNT'); throw new Error('CF_PRIVATE_COLLECTION_FAILED'); }
      this.collectionSteps.splice(0, this.collectionSteps.length, ...requests.map((_, i) => ({ step: CF_RUN_STEPS[i], host: CF_API_HOST })));
      cloudflareOffscreenStage(`COLLECT_OK_${requests.length}`);
      return requests;
    } catch (error) {
      const code = error instanceof Error && CF_PASSED_ERRORS.includes(error.message) ? error.message : 'CF_PRIVATE_COLLECTION_FAILED';
      this.failure = code === 'CF_PRIVATE_COLLECTION_FAILED' ? '' : code;
      cloudflareOffscreenStage(`COLLECT_${code}`);
      throw new Error(code);
    }
  }
  clear(): void {
    this.stopped = true;
    clearTimeout(this.deadline);
    this.collection?.clear();
    if (this.token) { void revokeCloudflareToken(this.token, cloudflareClientId()); this.token = ''; }
    super.clear();
  }
}
