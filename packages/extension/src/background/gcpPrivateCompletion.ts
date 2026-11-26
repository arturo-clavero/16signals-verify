import { sanitizeGcpPrivateResult } from '../offscreen/gcpPrivateResult';
import { sanitizeAwsPrivateResult } from '../aws-private/browser-client.mjs';
import { sanitizeCloudflarePrivateResult } from '../cloudflare-private/browser-client.mjs';

export const GCP_PRIVATE_ROUTE_TTL_MS = 13 * 60 * 1000;
export const AWS_PRIVATE_ROUTE_TTL_MS = 13 * 60 * 1000;
export const CF_PRIVATE_ROUTE_TTL_MS = 13 * 60 * 1000;
export type PrivateProvider = 'gcp' | 'aws' | 'cloudflare';
const FLAGS = { gcp: 'gcpPrivate', aws: 'awsPrivate', cloudflare: 'cfPrivate' } as const;
const PREFIX = { gcp: 'GCP_PRIVATE', aws: 'AWS_PRIVATE', cloudflare: 'CF_PRIVATE' } as const;
/** Run errors a provider passes to the page as they are (a message for the candidate, never a value). */
const PASSED: Record<PrivateProvider, readonly string[]> = { gcp: [], aws: ['AWS_ACTIVITY_ACCESS_REQUIRED'],
  cloudflare: ['CF_ACCOUNT_ACCESS_REQUIRED', 'CF_NO_ACTIVITY', 'CF_OAUTH_CANCELLED'] };
export const routeProvider = (route: GcpPrivateRoute | undefined): PrivateProvider | undefined =>
  route?.cfPrivate ? 'cloudflare' : route?.awsPrivate ? 'aws' : route?.gcpPrivate ? 'gcp' : undefined;
export interface GcpPrivateRoute { tabId: number; createdAt: number; pageProgress?: boolean; gcpPrivate?: boolean; awsPrivate?: boolean; cfPrivate?: boolean; windowId?: number; credentialsUsed?: boolean }
interface Sender { id?: string; url?: string; tab?: unknown }

export function livePrivateRoute(
  requestId: unknown, sender: Sender, routes: Map<string, GcpPrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
  provider: PrivateProvider = 'gcp',
) {
  if (typeof requestId !== 'string' || sender.id !== deps.extensionId || sender.tab !== undefined || sender.url !== deps.offscreenUrl) return null;
  const route = routes.get(requestId);
  // Exactly one provider flag, the one asked for.
  if (!route || routeProvider(route) !== provider || Object.values(FLAGS).filter(flag => route[flag]).length !== 1 ||
      !route.pageProgress || !Number.isInteger(route.tabId) || route.tabId < 0) return null;
  const ttl = provider === 'aws' ? AWS_PRIVATE_ROUTE_TTL_MS : provider === 'cloudflare' ? CF_PRIVATE_ROUTE_TTL_MS : GCP_PRIVATE_ROUTE_TTL_MS;
  if (deps.now - route.createdAt >= ttl || deps.now < route.createdAt) {
    routes.delete(requestId); return null;
  }
  return route;
}

/** A single-use route minted by autoApprovalFor, never restored from message data. */
export function takePrivateCompletion(
  raw: unknown, sender: Sender, routes: Map<string, GcpPrivateRoute>,
  deps: { extensionId: string; offscreenUrl: string; now: number },
  provider: PrivateProvider = 'gcp',
) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const message = raw as Record<string, unknown>;
  if (message.type !== `${PREFIX[provider]}_COMPLETE` || typeof message.requestId !== 'string') return null;
  const route = livePrivateRoute(message.requestId, sender, routes, deps, provider);
  if (!route) return null;
  routes.delete(message.requestId);
  let response: { success: true; result: ReturnType<typeof sanitizeGcpPrivateResult> | ReturnType<typeof sanitizeAwsPrivateResult> | ReturnType<typeof sanitizeCloudflarePrivateResult> } | { success: false; error: string };
  try {
    const keys = Reflect.ownKeys(message);
    if (message.success === true && keys.length === 4 && ['type', 'requestId', 'success', 'result'].every(key => keys.includes(key))) {
      const sanitize = provider === 'aws' ? sanitizeAwsPrivateResult : provider === 'cloudflare' ? sanitizeCloudflarePrivateResult : sanitizeGcpPrivateResult;
      response = { success: true, result: sanitize(message.result) };
    } else if (message.success === false && typeof message.error === 'string' && PASSED[provider].includes(message.error) &&
        keys.length === 4 && ['type', 'requestId', 'success', 'error'].every(key => keys.includes(key))) {
      response = { success: false, error: message.error };
    } else throw new Error();
  } catch { response = { success: false, error: `${PREFIX[provider]}_PROVING_FAILED` }; }
  return { requestId: message.requestId, tabId: route.tabId, response };
}

// Existing GCP callers retain their default policy and public names.
export { livePrivateRoute as liveGcpPrivateRoute, takePrivateCompletion as takeGcpPrivateCompletion };
