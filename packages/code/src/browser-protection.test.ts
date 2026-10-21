import assert from 'node:assert/strict';
import test from 'node:test';
import { SandboxManager } from '@anthropic-ai/sandbox-runtime';

import { browserSetupProtectedPaths } from './browser-setup.js';

test('browser setup credential files are in the effective SDK read-deny policy outside home', async t => {
  const paths = browserSetupProtectedPaths('/srv/code-state/profile.json.setup.json');
  const previous = SandboxManager.getConfig();
  t.after(async () => {
    await SandboxManager.reset();
    if (previous) SandboxManager.updateConfig(previous);
  });
  SandboxManager.updateConfig({
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowRead: [], allowWrite: [], denyWrite: paths },
    credentials: { files: paths.map(path => ({ path, mode: 'deny' as const })) },
  });
  const effective = SandboxManager.getFsReadConfig();
  for (const path of paths) assert.ok(effective.denyOnly.includes(path));
});
