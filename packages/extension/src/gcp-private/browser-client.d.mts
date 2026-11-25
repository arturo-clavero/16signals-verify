import type { GcpPrivateProofModule } from '../offscreen/gcpPrivateWitness';

export function createGcpPrivateModule(options: {
  projectId: string;
  policy: { cutoff: number; windowDays: number };
  workerUrl: string;
  fastSource?: { scopeHash: string; nonceMac: string };
  linkSecret?: Uint8Array;
  onProgress?: (value: { completedProofs: number }) => void;
}): GcpPrivateProofModule & { clear(): void };

export function readCloudLink(provider: 'gcp' | 'aws', binding: string): Promise<Uint8Array | null>;
