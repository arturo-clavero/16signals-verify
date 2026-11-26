type GcpRequest = { url: string; method: 'POST'; headers: Record<string, string>; body: string };
export const BATCHES: readonly { readonly step: string; readonly groupIds: readonly string[] }[];
export const GCP_ACCOUNTS_HOST: string;
export const GCP_CONSOLE_HOST: string;
export const GCP_CONSOLE_PATH: string;
export const GCP_BROWSER_LOG_HOST: string;
export const GCP_MAX_SENT: number;
export const GCP_MAX_RECV: number;
export const GCP_NONCE_HEADER: string;
export function gcpSessionRequest(account: string): GcpRequest;
export function gcpBatchRequest(step: string, policy: { cutoff: number; windowDays: number }, projectId: string,
  email: string, apiKey: string): GcpRequest;
