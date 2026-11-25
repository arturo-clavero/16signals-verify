import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { AWS_EVENT_STEP_LIMIT, AWS_MAX_EVENT_SESSIONS, AWS_SESSION_STEPS, AWS_EVENT_STEPS, awsSessionSteps } from './sessions.mjs';

test('one shared step list: identity, then E0 up to the session cap, never past E7', () => {
  assert.ok(AWS_MAX_EVENT_SESSIONS >= 1 && AWS_MAX_EVENT_SESSIONS <= AWS_EVENT_STEP_LIMIT);
  assert.deepEqual(AWS_SESSION_STEPS, awsSessionSteps(AWS_MAX_EVENT_SESSIONS));
  assert.deepEqual(AWS_EVENT_STEPS, AWS_SESSION_STEPS.slice(1));
  assert.deepEqual(awsSessionSteps(AWS_EVENT_STEP_LIMIT), ['identity', 'E0', 'E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7']);
  for (const cap of [0, 9, 1.5, '3']) assert.throws(() => awsSessionSteps(cap), /AWS_SESSION_CAP_INVALID/);
  assert.ok(Object.isFrozen(AWS_SESSION_STEPS) && Object.isFrozen(AWS_EVENT_STEPS));
});

test('runs at a smaller cap, the build cap and the E7 ceiling pass discovery, client and verifier end to end', () => {
  for (const cap of [2, AWS_MAX_EVENT_SESSIONS, AWS_EVENT_STEP_LIMIT]) {
    const result = spawnSync(process.execPath, ['--experimental-test-module-mocks', '--no-warnings',
      fileURLToPath(new URL('./sessions-cap-check.mjs', import.meta.url)), String(cap)], { encoding: 'utf8', timeout: 120000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).eventSessions, cap);
  }
});
