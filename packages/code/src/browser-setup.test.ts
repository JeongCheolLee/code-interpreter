import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createBridgeIdentity } from './identity.js';
import { browserSetupRequestHash, verifyBrowserSetupProof, verifyEnrollmentRedemption } from './browser-enrollment-protocol.js';
import type { BrowserSetupRequest, BrowserSetupProof } from './browser-enrollment-protocol.js';
import { browserSetupAttemptPath, loadBrowserSetupAttempt, setupBrowserWorker, setupInstanceUrl, cancelBrowserSetup } from './browser-setup.js';
import type { BrowserSetupOptions } from './browser-setup.js';
import { loadBridgeIdentity, saveBridgeIdentity, savePrivateJson } from './storage.js';
import { loadWorkerProfile } from './worker-profile.js';
import { parseSetupArguments } from './setup-cli.js';
import { runBrowserSetupCommand } from './browser-setup-cli.js';

async function fixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'browser-setup-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const options: BrowserSetupOptions = {
    instance: 'https://chat.example', machineName: 'headless-machine',
    profilePath: join(root, 'profile.json'),
    allowWorkspaceWrites: false, allowWorkspaceCommands: false,
  };
  let completeCalls = 0;
  let startCalls = 0;
  let initialRequest: BrowserSetupRequest | undefined;
  let lostStart = false;
  let lostComplete = false;
  let status: 'approved' | 'denied' | 'expired' | 'cancelled' = 'approved';
  const credential = { protocolVersion: 1 as const, workerId: 'approved-machine', credential: 'approved-credential-that-is-long-enough', expiresAt: '2099-01-01T00:00:00.000Z' };
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url).endsWith('/capabilities')) return Response.json({ browserEnrollmentVersion: 1 });
    const body = JSON.parse(String(init?.body)) as { request: BrowserSetupRequest; proof: BrowserSetupProof; signature: string; redemptionSignature?: string };
    assert.equal((body.request as unknown as Record<string, unknown>).privateKey, undefined);
    assert.equal(verifyBrowserSetupProof(body.request.publicKey, body.proof, body.signature), true);
    assert.equal(body.proof.requestHash, browserSetupRequestHash(body.request));
    const saved = await loadBrowserSetupAttempt(options.profilePath!);
    assert.equal(saved?.request.publicKey, body.request.publicKey, 'key saved before remote effect');
    assert.equal(saved?.request.attemptId, body.request.attemptId);
    initialRequest ??= body.request;
    assert.deepEqual(body.request, initialRequest, 'retries retain immutable request and key');
    const expiresAt = new Date(Date.parse(body.request.createdAt) + 600_000).toISOString();
    const approval = { operation: 'enrollment.redeem' as const, serverId: 'https://code.example', instance: body.request.instance,
      attemptId: body.request.attemptId, requestHash: browserSetupRequestHash(body.request), workerId: credential.workerId,
      expiresAt, codeApiUrl: 'https://code.example/v1' };
    const base = { version: 1, expiresAt, verificationCode: 'ABCD-EFGH', verificationUrl: `https://chat.example/code/setup/${body.request.attemptId}` };
    if (String(url).endsWith('/start')) {
      startCalls++;
      if (lostStart) { lostStart = false; throw new Error('lost issuance response'); }
      return Response.json({ ...base, status: 'pending' });
    }
    if (String(url).endsWith('/cancel')) return Response.json({ ...base, status: 'cancelled' });
    if (String(url).endsWith('/complete')) {
      completeCalls++;
      assert.equal(body.proof.operation, 'setup.complete');
      assert.equal(verifyEnrollmentRedemption(body.request.publicKey, approval, body.redemptionSignature!), true);
      if (lostComplete) { lostComplete = false; throw new Error('lost completion response'); }
      return Response.json({ ...base, status: 'completed', approval, credential });
    }
    return Response.json({ ...base, status, ...(status === 'approved' ? { approval } : {}) });
  }) as typeof fetch;
  return { root, options, fetchImpl, credential, counts: () => ({ completeCalls, startCalls }),
    loseStart: () => { lostStart = true; }, loseComplete: () => { lostComplete = true; }, setStatus: (value: typeof status) => { status = value; } };
}

test('headless setup displays URL and code and saves the existing least-privilege profile', async t => {
  const f = await fixture(t);
  let displayed = false;
  const saved = await setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0, onVerification: async value => {
    assert.match(value.verificationUrl, /^https:\/\/chat.example\/code\/setup\//);
    assert.equal(value.verificationCode, 'ABCD-EFGH');
    assert.ok(await loadBrowserSetupAttempt(f.options.profilePath!));
    displayed = true;
  } });
  assert.equal(displayed, true);
  assert.deepEqual(await loadWorkerProfile(saved.profilePath), saved.profile);
  assert.equal(saved.profile.allowWorkspaceCommands, false);
  assert.equal(saved.profile.allowWorkspaceWrites, false);
  assert.deepEqual(saved.profile.workspace, { type: 'private' });
  const identity = await loadBridgeIdentity(saved.profile.identityPath);
  assert.equal(identity.credential, f.credential.credential);
  assert.equal((await stat(browserSetupAttemptPath(saved.profilePath))).mode & 0o777, 0o600);
  assert.ok(!(await readFile(saved.profilePath, 'utf8')).includes('PRIVATE KEY'));
});

for (const boundary of ['start', 'complete'] as const) test(`lost ${boundary} response resumes the identical key and attempt`, async t => {
  const f = await fixture(t);
  if (boundary === 'start') f.loseStart(); else f.loseComplete();
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0 }), /lost/);
  const before = await loadBrowserSetupAttempt(f.options.profilePath!);
  assert.ok(before);
  await setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0 });
  const after = await loadBrowserSetupAttempt(f.options.profilePath!);
  assert.deepEqual(after?.request, before.request);
  assert.equal(after?.privateKey, before.privateKey);
  assert.equal(f.counts().startCalls, 2);
});

test('local profile failure after enrollment resumes without remote enrollment effects', async t => {
  const f = await fixture(t);
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0, saveProfile: async () => { throw new Error('disk full'); } }), /enrolled.*profile persistence failed/);
  assert.ok((await loadBrowserSetupAttempt(f.options.profilePath!))?.identity);
  assert.equal(f.counts().completeCalls, 1);
  const saved = await setupBrowserWorker(f.options, { fetchImpl: async () => { throw new Error('must not enroll again'); } });
  assert.ok(await loadWorkerProfile(saved.profilePath));
  assert.equal(f.counts().completeCalls, 1);
});

test('rerunning completed setup preserves a newer startup credential without network or redundant writes', async t => {
  const f = await fixture(t);
  const saved = await setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0 });
  const identity = { ...await loadBridgeIdentity(saved.profile.identityPath), credential: 'newer-credential-recovered-after-startup' };
  await saveBridgeIdentity(saved.profile.identityPath, identity);
  await setupBrowserWorker(f.options, {
    fetchImpl: async () => { assert.fail('completed setup does not enroll again'); },
    saveIdentity: async () => { assert.fail('do not replace a newer credential'); },
    saveProfile: async () => { assert.fail('do not rewrite an unchanged profile'); },
  });
  assert.deepEqual(await loadBridgeIdentity(saved.profile.identityPath), identity);
});

test('identity persistence failure after enrollment preserves the completed local receipt', async t => {
  const f = await fixture(t);
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0, saveIdentity: async () => { throw new Error('identity disk full'); } }), /disk full/);
  assert.ok((await loadBrowserSetupAttempt(f.options.profilePath!))?.identity);
  await setupBrowserWorker(f.options, { fetchImpl: async () => { throw new Error('must not enroll again'); } });
  assert.equal(f.counts().completeCalls, 1);
});

test('expired setup with a lost completion response recovers only existing key-bound enrollment', async t => {
  const f = await fixture(t);
  f.loseComplete();
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0 }), /lost/);
  const attempt = (await loadBrowserSetupAttempt(f.options.profilePath!))!;
  const now = Date.now();
  t.mock.method(Date, 'now', () => now + 11 * 60_000);
  const saved = await setupBrowserWorker(f.options, {
    fetchImpl: async () => { assert.fail('an expired attempt must not allocate another session'); },
    recoverCredential: async options => {
      assert.equal(options.privateKey, attempt.privateKey);
      assert.equal(options.workerId, attempt.approval?.workerId);
      assert.equal(options.codeApiUrl, attempt.approval?.codeApiUrl);
      return f.credential;
    },
  });
  assert.equal((await loadBridgeIdentity(saved.profile.identityPath)).publicKey, attempt.request.publicKey);
  assert.equal(f.counts().completeCalls, 1);
});

test('unsupported servers fail closed and never invoke manual redemption', async t => {
  const f = await fixture(t);
  let calls = 0;
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: async url => {
    calls++;
    assert.ok(String(url).endsWith('/capabilities'));
    return Response.json({ protocolVersion: 1 });
  } }), /will not downgrade/);
  assert.equal(calls, 1);
  assert.ok(await loadBrowserSetupAttempt(f.options.profilePath!));
});

for (const status of ['denied', 'expired', 'cancelled'] as const) test(`${status} setup preserves the saved identity and does not complete`, async t => {
  const f = await fixture(t);
  f.setStatus(status);
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl, pollIntervalMs: 0 }), new RegExp(status));
  assert.equal(f.counts().completeCalls, 0);
  assert.ok(await loadBrowserSetupAttempt(f.options.profilePath!));
});

test('retry cannot widen permissions, rename a machine, switch instances, or replace a key', async t => {
  const f = await fixture(t);
  f.loseStart();
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl }), /lost/);
  for (const change of [{ allowWorkspaceWrites: true }, { machineName: 'other-machine' }, { instance: 'https://other.example' }]) {
    await assert.rejects(setupBrowserWorker({ ...f.options, ...change }, { fetchImpl: async () => { assert.fail('no remote effects'); } }), /choices differ/);
  }
  const attempt = (await loadBrowserSetupAttempt(f.options.profilePath!))!;
  await savePrivateJson(browserSetupAttemptPath(f.options.profilePath!), { ...attempt, privateKey: createBridgeIdentity().privateKey });
  await assert.rejects(loadBrowserSetupAttempt(f.options.profilePath!), /key does not match/);
});

test('cancellation is signed by the persisted machine key', async t => {
  const f = await fixture(t);
  f.loseStart();
  await assert.rejects(setupBrowserWorker(f.options, { fetchImpl: f.fetchImpl }), /lost/);
  await cancelBrowserSetup(f.options.profilePath!, undefined, f.fetchImpl);
});

test('cancellation after enrollment saves the profile but prevents requested foreground startup', { timeout: 5000 }, async t => {
  const f = await fixture(t);
  const controller = new AbortController();
  t.mock.method(globalThis, 'fetch', async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const response = await f.fetchImpl(input, init);
    if (String(input).endsWith('/complete')) controller.abort(new Error('owner cancelled startup'));
    return response;
  });
  await assert.rejects(runBrowserSetupCommand(new Map<string, string | true>([
    ['--instance', f.options.instance], ['--machine-name', f.options.machineName],
    ['--profile', f.options.profilePath!], ['--default-workspace', true], ['--start', true],
  ]), {
    interactive: false, signal: controller.signal,
    ask: async () => { assert.fail('no prompt expected'); },
    yesNo: async () => { assert.fail('no prompt expected'); },
  }), /owner cancelled startup/);
  assert.ok(await loadWorkerProfile(f.options.profilePath!));
});

test('browser flags preserve manual automation without accepting mixed credentials', () => {
  const flags = parseSetupArguments(['--instance', 'https://chat.example', '--non-interactive', '--default-workspace', '--no-browser']);
  assert.equal(flags.get('--instance'), 'https://chat.example');
  for (const manual of ['--url=https://code.example/v1', '--worker-id=worker', '--code-stdin'])
    assert.throws(() => parseSetupArguments(['--instance=https://chat.example', manual]), /manual pairing/);
  assert.throws(() => parseSetupArguments(['--no-browser']), /require --instance/);
  assert.equal(setupInstanceUrl('https://chat.example/'), 'https://chat.example');
  assert.throws(() => setupInstanceUrl('https://user:secret@chat.example'), /credentials/);
});
