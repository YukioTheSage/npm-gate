# Phase 7 Enforced Sandbox Install Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an install execution mode that delegates with a scrubbed environment, isolated home, `--ignore-scripts` defaults, and explicit platform-limit reporting.

**Architecture:** Keep current `--sandbox-plan` as non-executing output. Add `--sandbox-execute` to `install` and `add`, implemented by a new sandbox runner that prepares an environment and then calls the existing package-manager runner.

**Tech Stack:** TypeScript, Node fs/os/path, Vitest mocks, existing package-manager runner.

---

## File Structure

- Create: `src/sandbox/sandbox-environment.ts` - environment scrubbing and temp home creation.
- Modify: `src/sandbox/sandbox-runner.ts` - add execution renderer or result type without replacing plan rendering.
- Modify: `src/cli/commands/install.ts` - add `--sandbox-execute`.
- Modify: `src/wrappers/package-manager-runner.ts` - accept optional env override.
- Test: `tests/unit/sandbox-environment.test.ts` - secret scrubbing and args.
- Test: `tests/unit/package-manager-runner-env.test.ts` - command routing with env override.
- Test: `tests/unit/install-command.test.ts` - command routing.
- Modify: `docs/examples.md`, `docs/ci-usage.md`, `docs/policy.md`, and `README.md` - usage and limits.

### Task 1: Add Environment Scrubber

- [ ] **Step 1: Write failing unit test**

Create `tests/unit/sandbox-environment.test.ts`:

```ts
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
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/sandbox-environment.test.ts
```

Expected: fail because sandbox environment does not exist.

- [ ] **Step 3: Implement scrubber**

Create `src/sandbox/sandbox-environment.ts`:

```ts
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const secretEnvPatterns = [
  /^NPM_TOKEN$/i,
  /^NODE_AUTH_TOKEN$/i,
  /^GITHUB_TOKEN$/i,
  /^GH_TOKEN$/i,
  /^AWS_/i,
  /^AZURE_/i,
  /^GOOGLE_APPLICATION_CREDENTIALS$/i,
  /^SSH_AUTH_SOCK$/i
];

export interface SandboxEnvironment {
  env: Record<string, string>;
  home: string;
  limitations: string[];
}

export async function createSandboxEnvironment(input: {
  cwd: string;
  env: NodeJS.ProcessEnv | Record<string, string | undefined>;
}): Promise<SandboxEnvironment> {
  const home = await mkdtemp(join(tmpdir(), 'npm-gate-home-'));
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(input.env)) {
    if (value === undefined) continue;
    if (secretEnvPatterns.some((pattern) => pattern.test(key))) continue;
    env[key] = value;
  }
  env.HOME = home;
  env.USERPROFILE = home;
  return {
    env,
    home,
    limitations: ['network allowlisting is not enforced by npm-gate on this platform']
  };
}
```

- [ ] **Step 4: Run unit test**

Run:

```sh
pnpm test tests/unit/sandbox-environment.test.ts
```

Expected: pass.

### Task 2: Add Package Manager Env Override

- [ ] **Step 1: Write failing runner test**

Create `tests/unit/package-manager-runner-env.test.ts` with a mocked child process before dynamically importing the runner:

```ts
import { EventEmitter } from 'node:events';
import { describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  spawn: vi.fn()
}));

vi.mock('node:child_process', () => ({
  spawn: mocks.spawn
}));

const { runPackageManager } = await import('../../src/wrappers/package-manager-runner.js');

describe('package manager runner env override', () => {
  test('passes explicit env to package manager child process', async () => {
    const child = new EventEmitter();
    mocks.spawn.mockReturnValue(child);

    const result = runPackageManager('npm', ['install', '--ignore-scripts'], process.cwd(), {
      env: { PATH: 'safe-path', HOME: 'sandbox-home' }
    });
    child.emit('close', 0);

    await expect(result).resolves.toBe(0);
    expect(mocks.spawn).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Array),
      expect.objectContaining({
        env: { PATH: 'safe-path', HOME: 'sandbox-home' }
      })
    );
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/package-manager-runner-env.test.ts
```

Expected: fail because `runPackageManager` does not accept options.

- [ ] **Step 3: Add options**

Modify `src/wrappers/package-manager-runner.ts`:

```ts
export interface RunPackageManagerOptions {
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
}

export async function runPackageManager(
  packageManager: PackageManager,
  args: string[],
  cwd: string,
  options: RunPackageManagerOptions = {}
): Promise<number> {
  const env = options.env ?? process.env;
  let resolved;
  try {
    resolved = await resolveCommandForSpawn(packageManager, args, { env });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${redactSecrets(message)}\n`);
    return 2;
  }

  return new Promise((resolve) => {
    const child = spawn(resolved.command, resolved.args, {
      cwd,
      stdio: 'inherit',
      shell: false,
      env: { ...env }
    });
    child.on('error', (error) => {
      process.stderr.write(`${redactSecrets(error.message)}\n`);
      resolve(2);
    });
    child.on('close', (code) => resolve(code ?? 2));
  });
}
```

- [ ] **Step 4: Run runner tests**

Run:

```sh
pnpm test tests/unit/package-manager-runner-env.test.ts tests/unit/package-manager-runner.test.ts
```

Expected: pass.

### Task 3: Add `--sandbox-execute`

- [ ] **Step 1: Write failing install-command test**

Add to `tests/unit/install-command.test.ts`:

```ts
test('sandbox execute delegates with ignore scripts and scrubbed env after policy allows', async () => {
  mocks.evaluatePackages.mockResolvedValue({
    startedAt: '2026-05-14T00:00:00.000Z',
    toolVersion: '0.1.0',
    mode: 'warn',
    configSource: 'default',
    findings: [],
    summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
  });
  mocks.runPackageManager.mockResolvedValue(0);
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

  await makeProgram().parseAsync(['install', 'left-pad', '--sandbox-execute'], { from: 'user' });

  expect(mocks.runPackageManager).toHaveBeenCalledWith(
    'npm',
    ['install', 'left-pad', '--ignore-scripts'],
    process.cwd(),
    expect.objectContaining({ env: expect.objectContaining({ HOME: expect.any(String) }) })
  );
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/install-command.test.ts
```

Expected: fail because option is unknown.

- [ ] **Step 3: Implement command option**

In `src/cli/commands/install.ts`, add:

```ts
sandboxExecute?: boolean;
```

Add Commander option:

```ts
.option('--sandbox-execute', 'run the package manager with scrubbed environment and ignore-scripts defaults')
```

Before delegation:

```ts
if (options.sandboxExecute) {
  const sandbox = await createSandboxEnvironment({ cwd: process.cwd(), env: process.env });
  const sandboxArgs = allArgs.includes('--ignore-scripts') ? allArgs : [...allArgs, '--ignore-scripts'];
  process.exitCode = await runPackageManager(
    packageManager,
    [command, ...sandboxArgs],
    process.cwd(),
    { env: sandbox.env }
  );
  return;
}
```

- [ ] **Step 4: Surface limitations**

Write a concise console line before delegation:

```ts
process.stderr.write(`npm-gate sandbox limitation: ${sandbox.limitations.join('; ')}\n`);
```

Do not print secret values.

- [ ] **Step 5: Run verification**

Run:

```sh
pnpm test tests/unit/sandbox-environment.test.ts tests/unit/package-manager-runner-env.test.ts tests/unit/package-manager-runner.test.ts tests/unit/install-command.test.ts
pnpm typecheck
```

Expected: pass.

- [ ] **Step 6: Commit**

```sh
git add src/sandbox/sandbox-environment.ts src/sandbox/sandbox-runner.ts src/cli/commands/install.ts src/wrappers/package-manager-runner.ts tests/unit/sandbox-environment.test.ts tests/unit/package-manager-runner-env.test.ts tests/unit/package-manager-runner.test.ts tests/unit/install-command.test.ts docs/examples.md docs/ci-usage.md docs/policy.md README.md
git commit -m "feat: add sandboxed install execution mode"
```
