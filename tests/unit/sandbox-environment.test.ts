import { describe, expect, test } from 'vitest';
import { createSandboxEnvironment } from '../../src/sandbox/sandbox-environment.js';

describe('sandbox environment', () => {
  test('removes publish tokens, cloud credentials, and ssh agent variables', async () => {
    const sandbox = await createSandboxEnvironment({
      cwd: process.cwd(),
      env: {
        NPM_TOKEN: 'secret',
        NODE_AUTH_TOKEN: 'secret',
        GITHUB_TOKEN: 'secret',
        AWS_SECRET_ACCESS_KEY: 'secret',
        SSH_AUTH_SOCK: '/tmp/agent',
        PATH: 'safe-path'
      }
    });

    expect(sandbox.env.NPM_TOKEN).toBeUndefined();
    expect(sandbox.env.NODE_AUTH_TOKEN).toBeUndefined();
    expect(sandbox.env.GITHUB_TOKEN).toBeUndefined();
    expect(sandbox.env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(sandbox.env.SSH_AUTH_SOCK).toBeUndefined();
    expect(sandbox.env.PATH).toBe('safe-path');
    expect(sandbox.env.HOME).toContain('npm-gate-home-');
    expect(sandbox.env.USERPROFILE).toBe(sandbox.env.HOME);
    expect(sandbox.limitations).toContain(
      'network allowlisting is not enforced by npm-gate on this platform'
    );
  });
});
