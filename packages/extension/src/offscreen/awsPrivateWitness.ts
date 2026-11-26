import { PrivateWitnessRun } from './gcpPrivateWitness';
import { AWS_PAGE_STEPS, awsCollectedSteps, awsSessionHost, sanitizeAwsPrivateResult, validateAwsAttempt, createAwsLocalSession, type AwsPrivateAttempt, type AwsPrivateModule, type AwsCapture } from '../aws-private/browser-client.mjs';

export const AWS_PRIVATE_TIMEOUT_MS = 13 * 60 * 1000;

/** One fixed diagnostic code per AWS run stage for the offscreen console; never a value. */
export function awsOffscreenStage(code: string): void {
  try { console.warn(`AWS_OFF_${code}`); } catch { /* Diagnostics must not affect the run. */ }
}
const stageCode = (error: unknown) => {
  const stage = (error as { stage?: unknown } | null)?.stage;
  return typeof stage === 'string' && /^[A-Z0-9_]{1,80}$/.test(stage) ? stage : 'UNSPECIFIED';
};

const ATTEMPT_KEYS = ['proofId', 'pluginSha256', 'nonceMac', 'identityService', 'region', 'issuedAt', 'expiresAt'];
/**
 * The plugin's `privateAttempt`: exactly the server attempt fields, plus optional `jobGroups` (1-64 catalog group ids,
 * a ranking weight only). Anything else, another request or another plugin is refused.
 */
export function awsPrivateAttemptParam(value: unknown, requestId: string | null | undefined, pluginSha256: string): AwsPrivateAttempt {
  const attempt = value as Record<string, unknown> | null;
  const groups = attempt && typeof attempt === 'object' && Object.hasOwn(attempt, 'jobGroups') ? attempt.jobGroups : undefined;
  const keys = groups === undefined ? ATTEMPT_KEYS : [...ATTEMPT_KEYS, 'jobGroups'];
  if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt) ||
      Object.keys(attempt).length !== keys.length || !keys.every(key => Object.hasOwn(attempt, key)) ||
      (groups !== undefined && (!Array.isArray(groups) || groups.length < 1 || groups.length > 64 ||
        groups.some(group => typeof group !== 'string' || !/^[a-z0-9][a-z0-9-]{0,39}$/.test(group)))) ||
      attempt.proofId !== requestId || attempt.pluginSha256 !== pluginSha256) throw new Error('AWS_PRIVATE_PROVING_FAILED');
  return attempt as unknown as AwsPrivateAttempt;
}

/** Compiled runner policy; page/plugin data cannot select the witness implementation. */
export class AwsPrivateWitnessRun extends PrivateWitnessRun {
  private deadline: ReturnType<typeof setTimeout>;
  private collection?: ReturnType<typeof createAwsLocalSession>;
  private attempt: AwsPrivateAttempt;
  private stopped = false;
  private collectionAccessRequired = false;
  private readonly fastCheck: boolean;
  get activityAccessRequired(): boolean { return this.collectionAccessRequired; }
  private readonly collectionSteps: { step: string; host: string }[];
  private readonly awsModule: AwsPrivateModule;
  constructor(run: Record<string, string>, requestId: string | null, attempt: AwsPrivateAttempt, module: AwsPrivateModule) {
    validateAwsAttempt(attempt);
    if (run.proofId !== attempt.proofId || run.pluginSha256 !== attempt.pluginSha256 ||
        typeof module.getRevealPlan !== 'function') throw new Error('AWS_PRIVATE_PROVING_FAILED');
    const steps = [{ step: 'identity', host: 'iam.amazonaws.com' }, { step: 'E0', host: 'cloudtrail.us-east-1.amazonaws.com' }];
    super(run, requestId, module, {
      method: 'AWS_ACCOUNT', nonceMac: attempt.nonceMac, proveTimeoutMs: AWS_PRIVATE_TIMEOUT_MS,
      steps, pageSteps: AWS_PAGE_STEPS,
      finish(result, sessionIds) {
        const envelope = sanitizeAwsPrivateResult(result);
        if (envelope.sessionIds.length !== sessionIds.length || envelope.sessionIds.some((id, index) => id !== sessionIds[index])) throw new Error('AWS_PRIVATE_PROVING_FAILED');
        return envelope;
      },
    });
    this.collectionSteps = steps;
    this.awsModule = module;
    this.fastCheck = module.fastCheck === true;
    this.attempt = { ...attempt };
    this.deadline = setTimeout(() => this.clear(), Math.min(AWS_PRIVATE_TIMEOUT_MS, attempt.expiresAt - Date.now()));
  }
  async collect(capture: () => Promise<AwsCapture>) {
    if (this.stopped || this.collection) { awsOffscreenStage('COLLECT_BUSY'); throw new Error('AWS_PRIVATE_COLLECTION_FAILED'); }
    this.collection = createAwsLocalSession({ attempt: this.attempt, identityOnly: this.fastCheck });
    let value: AwsCapture;
    try { value = await capture(); } catch (error) { awsOffscreenStage('CAPTURE_FAILED'); throw error; }
    try {
      let requests;
      try { requests = await this.collection.prepare(value); }
      catch (error) {
        awsOffscreenStage(error instanceof Error && error.message === 'AWS_ACTIVITY_ACCESS_REQUIRED' ? 'PREPARE_ACTIVITY_ACCESS_REQUIRED' : `PREPARE_${stageCode(error)}`);
        throw error;
      }
      const steps = awsCollectedSteps(requests);
      if (this.stopped || requests.length < (this.fastCheck ? 1 : 2) || requests.length > steps.length) {
        awsOffscreenStage(this.stopped ? 'COLLECT_STOPPED' : `COLLECT_COUNT_${requests.length}`);
        throw new Error('AWS_PRIVATE_COLLECTION_FAILED');
      }
      // A page run's planner proves the rows the local selection chose in each page.
      const rows = this.collection.pageRows?.();
      if (rows) this.awsModule.selectPages(rows);
      awsOffscreenStage(`COLLECT_OK_${requests.length}`);
      // A page session reads CloudTrail in its own Region; every other step has one fixed host.
      this.collectionSteps.splice(0, this.collectionSteps.length, ...requests.map((request, index) => ({
        step: steps[index], host: awsSessionHost(steps[index], URL.canParse(request?.url) ? new URL(request.url).hostname : ''),
      })));
      return requests;
    } catch (error) {
      this.collectionAccessRequired = error instanceof Error && error.message === 'AWS_ACTIVITY_ACCESS_REQUIRED';
      throw new Error(this.collectionAccessRequired ? 'AWS_ACTIVITY_ACCESS_REQUIRED' : 'AWS_PRIVATE_COLLECTION_FAILED');
    }
    finally { if (value?.credentials) for (const key of Object.keys(value.credentials)) value.credentials[key as keyof AwsCapture['credentials']] = ''; }
  }
  clear(): void {
    this.stopped = true;
    clearTimeout(this.deadline);
    this.collection?.clear();
    super.clear();
  }
}
