import { useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { SessionManager } from '../../offscreen/SessionManager';
import { logger } from '@tlsn/common';
import { getStoredLogLevel } from '../../utils/logLevelStorage';
import type { OffscreenMessage } from '../../types/messages';
import { prepareBuiltInRun, readPackagedFile } from '../../offscreen/builtinRun';
import { runSessionData } from '../../offscreen/pluginHash';
import { createGcpPrivateModule, readCloudLink } from '../../gcp-private/browser-client.mjs';
import { gcpPrivateDiagnostic } from '../../offscreen/gcpPrivateWitness';
import { createAwsPrivateModule } from '../../aws-private/browser-client.mjs';
import { AwsPrivateWitnessRun, awsOffscreenStage, awsPrivateAttemptParam } from '../../offscreen/awsPrivateWitness';
import { createCloudflarePrivateModule, readCloudLink as readCloudflareLink } from '../../cloudflare-private/browser-client.mjs';
import { CloudflarePrivateWitnessRun, cloudflareOffscreenStage, cloudflarePrivateAttemptParam } from '../../offscreen/cloudflarePrivateWitness';

const OffscreenApp: React.FC = () => {
  useEffect(() => {
    // Initialize logger with stored log level
    getStoredLogLevel().then((level) => {
      logger.init(level);
      logger.info('Offscreen document loaded');
    });

    // Initialize SessionManager
    const sessionManager = new SessionManager();
    let privateRunning = false;
    logger.debug('SessionManager initialized in Offscreen');

    // Listen for messages from background script
    browser.runtime.onMessage.addListener((msg: unknown, sender: browser.Runtime.MessageSender) => {
      const request = msg as OffscreenMessage;
      // Example message handling
      if (request.type === 'PROCESS_DATA') {
        return Promise.resolve({
          success: true,
          data: 'Processed in offscreen',
        });
      }

      // Relay: inbound MPC bytes from the verifier (forwarded by the
      // background under a distinct type so each chunk is delivered exactly once
      // — the content script's runtime.sendMessage is ALSO broadcast directly to
      // this offscreen, so we must NOT also handle the raw RELAY_IN here).
      if (request.type === 'RELAY_DELIVER') {
        sessionManager.handleRelayIn(request.data as string);
        return;
      }
      if (request.type === 'RELAY_DELIVER_CLOSED') {
        sessionManager.handleRelayClosed();
        return;
      }

      // Run one of the built-in plugins. The
      // message carries the plugin id, fingerprint and values, never code; the
      // code is read from the package here (offscreen/builtinRun.ts). No
      // handler runs code taken from a message (the stock code-execution and
      // plugin-stats handlers are gone).
      if (request.type === 'RUN_BUILTIN_OFFSCREEN') {
        const prepare = (value: typeof request) => prepareBuiltInRun(value, sender, {
          extensionId: browser.runtime.id,
          backgroundUrl: browser.runtime.getURL('background.bundle.js'),
          readPackaged: readPackagedFile,
        });
        return prepare(request).then(async (prepared) => {
          if ('error' in prepared) {
            logger.warn('RUN_BUILTIN_OFFSCREEN refused:', prepared.error);
            return { success: false, error: prepared.error, requestId: request.requestId };
          }
          let activeCode = prepared.code;
          const execute = async (privateModule?: ReturnType<typeof createGcpPrivateModule> | AwsPrivateWitnessRun | CloudflarePrivateWitnessRun) => {
            const sm = await sessionManager.awaitInit();
            return sm.executePlugin(activeCode, request.requestId ?? undefined,
              runSessionData(request.sessionData, prepared.sha256), privateModule);
          };
          // 16signals fork (Cloudflare): OAuth token from the background, local discovery, page sessions, proofs here.
          if (request.pluginId === 'cloudflare-private-work') {
            if (privateRunning || !request.requestId) return { success: false, error: 'CF_PRIVATE_PROVING_FAILED' };
            let run: CloudflarePrivateWitnessRun | undefined;
            let linkSecret: Uint8Array | null = null;
            try {
              const params = JSON.parse(request.values.params);
              const attempt = cloudflarePrivateAttemptParam(params?.privateAttempt, request.requestId, prepared.sha256);
              // Fast check (demo replay): only when this browser saved the link to the recorded run's identity id.
              const binding = params?.fastSource?.identityHash;
              linkSecret = typeof binding === 'string' ? await readCloudflareLink('cloudflare', binding) : null;
              const fastSource = linkSecret ? { identityHash: binding as string, length: params.fastSource.length } : undefined;
              const effective = await prepare({ ...request, values: { ...request.values,
                params: JSON.stringify({ ...params, fastCheck: !!fastSource }) } });
              if ('error' in effective) throw new Error();
              activeCode = effective.code;
              const module = createCloudflarePrivateModule({ attempt, fastSource, linkSecret: linkSecret ?? undefined,
                workerUrl: browser.runtime.getURL('cloudflare-private/browser-worker.js'),
                onProgress: ({ completedProofs }) => {
                  browser.runtime.sendMessage({ type: 'PLUGIN_PROGRESS', requestId: request.requestId,
                    progress: { method: 'CLOUDFLARE_ACCOUNT', status: 'busy', index: completedProofs, total: 64 } }).catch(() => {});
                },
              });
              try { run = new CloudflarePrivateWitnessRun(runSessionData(request.sessionData, prepared.sha256), request.requestId, attempt, module); }
              catch { module.clear(); throw new Error(); }
            } catch { cloudflareOffscreenStage('MODULE_FAILED'); linkSecret?.fill(0); run?.clear(); return { success: false, error: 'CF_PRIVATE_PROVING_FAILED' }; }
            privateRunning = true;
            const heartbeat = setInterval(() => {
              browser.runtime.sendMessage({ type: 'CF_PRIVATE_HEARTBEAT', requestId: request.requestId })
                .then(reply => { if (!reply || typeof reply !== 'object' || !('ok' in reply) || reply.ok !== true) run!.clear(); })
                .catch(() => run!.clear());
            }, 20_000);
            void (async () => {
              try {
                const result = await execute(run!);
                await browser.runtime.sendMessage({ type: 'CF_PRIVATE_COMPLETE', requestId: request.requestId, success: true, result });
              } catch {
                cloudflareOffscreenStage('EXECUTE_FAILED');
                await browser.runtime.sendMessage({ type: 'CF_PRIVATE_COMPLETE', requestId: request.requestId,
                  success: false, error: run!.passedError || 'CF_PRIVATE_PROVING_FAILED' }).catch(() => {});
              } finally { clearInterval(heartbeat); run!.clear(); privateRunning = false; }
            })();
            return { success: true, pending: true, requestId: request.requestId };
          }
          if (request.pluginId === 'gcp-work' || request.pluginId === 'aws-private-work') {
            const aws = request.pluginId === 'aws-private-work';
            const privateError = aws ? 'AWS_PRIVATE_PROVING_FAILED' : 'GCP_PRIVATE_PROVING_FAILED';
            const prefix = aws ? 'AWS_PRIVATE' : 'GCP_PRIVATE';
            if (privateRunning || !request.requestId) {
              if (!aws) gcpPrivateDiagnostic(privateRunning ? 'RUN_BUSY' : 'RUN_ID_MISSING');
              return { success: false, error: privateError };
            }
            let privateModule: ReturnType<typeof createGcpPrivateModule> | AwsPrivateWitnessRun | undefined;
            try {
              const params = JSON.parse(request.values.params);
              const binding = aws ? params.fastSource?.userIdHash : params.fastSource?.scopeHash;
              const linkSecret = typeof binding === 'string' ? await readCloudLink(aws ? 'aws' : 'gcp', binding) : null;
              const fastSource = linkSecret ? params.fastSource : undefined;
              const effective = await prepare({ ...request, values: { ...request.values,
                params: JSON.stringify({ ...params, fastCheck: !!fastSource }) } });
              if ('error' in effective) { linkSecret?.fill(0); throw new Error(); }
              activeCode = effective.code;
              if (aws) {
                const attempt = awsPrivateAttemptParam(params?.privateAttempt, request.requestId, prepared.sha256);
                const module = createAwsPrivateModule({ attempt, fastSource, linkSecret: linkSecret ?? undefined, workerUrl: browser.runtime.getURL('aws-private/browser-worker.js'),
                  onProgress: ({ completedProofs }) => {
                    browser.runtime.sendMessage({ type: 'PLUGIN_PROGRESS', requestId: request.requestId,
                      progress: { method: 'AWS_ACCOUNT', status: 'busy', index: completedProofs, total: 128 } }).catch(() => {});
                  },
                });
                try { privateModule = new AwsPrivateWitnessRun(runSessionData(request.sessionData, prepared.sha256), request.requestId, attempt, module); }
                catch { module.clear(); throw new Error(); }
              } else {
              if (!params || typeof params !== 'object' || !params.privateInput ||
                  Object.keys(params.privateInput).length !== 1 || typeof params.privateInput.projectId !== 'string') throw new Error();
              privateModule = createGcpPrivateModule({
                projectId: params.privateInput.projectId, fastSource, linkSecret: linkSecret ?? undefined,
                policy: { cutoff: params.cutoff, windowDays: params.windowDays },
                workerUrl: browser.runtime.getURL('gcp-private/browser-worker.js'),
                onProgress: ({ completedProofs }) => {
                  sessionManager.updateGcpProofProgress(request.requestId!, completedProofs);
                  browser.runtime.sendMessage({ type: 'PLUGIN_PROGRESS', requestId: request.requestId,
                    progress: { method: 'GCP_WORK', status: 'busy', index: completedProofs, total: 128 } }).catch(() => {});
                },
              });
              }
            } catch { if (aws) awsOffscreenStage('MODULE_FAILED'); else gcpPrivateDiagnostic('MODULE_FAILED'); privateModule?.clear(); return { success: false, error: privateError }; }
            privateRunning = true;
            const heartbeat = setInterval(() => {
              browser.runtime.sendMessage({ type: `${prefix}_HEARTBEAT`, requestId: request.requestId })
                .then(reply => {
                  if (!reply || typeof reply !== 'object' || !('ok' in reply) || reply.ok !== true) {
                    if (!aws) gcpPrivateDiagnostic('HEARTBEAT_NOT_OK');
                    privateModule!.clear();
                  }
                }).catch(() => { if (!aws) gcpPrivateDiagnostic('HEARTBEAT_REJECTED'); privateModule!.clear(); });
            }, 20_000);
            // Return the acknowledgement before awaiting capture/proving: one
            // service-worker request must not remain open past Chrome's five minutes.
            void (async () => {
              try {
                const result = await execute(privateModule!);
                await browser.runtime.sendMessage({ type: `${prefix}_COMPLETE`, requestId: request.requestId, success: true, result });
              } catch {
                if (aws) awsOffscreenStage('EXECUTE_FAILED'); else gcpPrivateDiagnostic('EXECUTE_FAILED');
                const failure = aws && privateModule instanceof AwsPrivateWitnessRun && privateModule.activityAccessRequired
                  ? 'AWS_ACTIVITY_ACCESS_REQUIRED' : privateError;
                await browser.runtime.sendMessage({ type: `${prefix}_COMPLETE`, requestId: request.requestId,
                  success: false, error: failure }).catch(() => {});
              } finally { clearInterval(heartbeat); privateModule!.clear(); privateRunning = false; }
            })();
            return { success: true, pending: true, requestId: request.requestId };
          }
          try {
            const result = await execute();
            logger.debug('Plugin execution result:', result);
            return { success: true, result, requestId: request.requestId };
          } catch (error) {
            logger.error('Plugin execution error:', error);
            return {
              success: false,
              error: error instanceof Error ? error.message : String(error),
              requestId: request.requestId,
            };
          }
        });
      }
    });
  }, []);

  return (
    <div className="offscreen-container">
      <h1>Offscreen Document</h1>
      <p>This document runs in the background for processing tasks.</p>
    </div>
  );
};

const container = document.getElementById('app-container');
if (container) {
  const root = createRoot(container);
  root.render(<OffscreenApp />);
}
