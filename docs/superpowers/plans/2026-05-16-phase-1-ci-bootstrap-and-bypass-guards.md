# Phase 1 CI Bootstrap And Bypass Guards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent unsafe CI bootstrap patterns and reject `NPM_GATE_MODE=off` in CI or release contexts.

**Architecture:** Keep the guard near CLI command entry points so bypass behavior is blocked before package-manager delegation. Update docs and examples so users bootstrap with `--ignore-scripts`, build the local CLI, and run `ci --release-audit` before any script-enabled install.

**Tech Stack:** TypeScript, Commander, Vitest, Markdown, GitHub Actions YAML.

---

## File Structure

- Modify: `src/cli/commands/install.ts` - block direct delegation when off mode is unsafe.
- Create: `src/cli/ci-bypass-guard.ts` - pure helper for CI/release bypass detection.
- Test: `tests/unit/ci-bypass-guard.test.ts` - helper coverage.
- Modify: `tests/unit/install-command.test.ts` - command-level guard coverage.
- Modify: `examples/ci-gate/github-actions.yml` - safe bootstrap example.
- Modify: `docs/ci-usage.md` - reinforce safe CI usage.
- Modify: `README.md` - keep quickstart aligned with safe CI usage.

### Task 1: Add CI Bypass Guard Helper

- [ ] **Step 1: Write the failing helper test**

Add `tests/unit/ci-bypass-guard.test.ts`:

```ts
import { describe, expect, test } from 'vitest';
import { assertModeOffAllowed } from '../../src/cli/ci-bypass-guard.js';

describe('CI bypass guard', () => {
  test('rejects off mode in GitHub Actions', () => {
    expect(() =>
      assertModeOffAllowed({ NPM_GATE_MODE: 'off', GITHUB_ACTIONS: 'true' })
    ).toThrow(/NPM_GATE_MODE=off is forbidden/);
  });

  test('rejects off mode in generic CI', () => {
    expect(() => assertModeOffAllowed({ NPM_GATE_MODE: 'off', CI: 'true' })).toThrow(
      /NPM_GATE_MODE=off is forbidden/
    );
  });

  test('rejects off mode during release jobs', () => {
    expect(() =>
      assertModeOffAllowed({ NPM_GATE_MODE: 'off', NPM_GATE_RELEASE: 'true' })
    ).toThrow(/NPM_GATE_MODE=off is forbidden/);
  });

  test('allows off mode locally', () => {
    expect(() => assertModeOffAllowed({ NPM_GATE_MODE: 'off' })).not.toThrow();
  });
});
```

- [ ] **Step 2: Run the helper test to verify it fails**

Run:

```sh
pnpm test tests/unit/ci-bypass-guard.test.ts
```

Expected: fail because `src/cli/ci-bypass-guard.ts` does not exist.

- [ ] **Step 3: Implement the helper**

Create `src/cli/ci-bypass-guard.ts`:

```ts
const truthy = new Set(['1', 'true', 'yes']);

function isTruthy(value: string | undefined): boolean {
  return value ? truthy.has(value.toLowerCase()) : false;
}

export function isCiOrReleaseEnv(env: NodeJS.ProcessEnv | Record<string, string | undefined>): boolean {
  return (
    isTruthy(env.CI) ||
    isTruthy(env.GITHUB_ACTIONS) ||
    isTruthy(env.NPM_GATE_RELEASE) ||
    isTruthy(env.RELEASE) ||
    isTruthy(env.CI_RELEASE)
  );
}

export function assertModeOffAllowed(
  env: NodeJS.ProcessEnv | Record<string, string | undefined>
): void {
  if (env.NPM_GATE_MODE === 'off' && isCiOrReleaseEnv(env)) {
    throw new Error(
      'NPM_GATE_MODE=off is forbidden in CI or release contexts. Remove the bypass or run outside CI.'
    );
  }
}
```

- [ ] **Step 4: Run the helper test to verify it passes**

Run:

```sh
pnpm test tests/unit/ci-bypass-guard.test.ts
```

Expected: pass.

### Task 2: Apply Guard To Install Delegation

- [ ] **Step 1: Write the failing command test**

Add this test to `tests/unit/install-command.test.ts`:

```ts
test('does not honor NPM_GATE_MODE=off in CI', async () => {
  const originalMode = process.env.NPM_GATE_MODE;
  const originalCi = process.env.CI;
  process.env.NPM_GATE_MODE = 'off';
  process.env.CI = 'true';
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

  await expect(makeProgram().parseAsync(['install', 'left-pad'], { from: 'user' })).rejects.toThrow(
    /NPM_GATE_MODE=off is forbidden/
  );

  expect(mocks.runPackageManager).not.toHaveBeenCalled();
  process.env.NPM_GATE_MODE = originalMode;
  process.env.CI = originalCi;
});
```

- [ ] **Step 2: Run the command test to verify it fails**

Run:

```sh
pnpm test tests/unit/install-command.test.ts
```

Expected: fail because off mode still delegates directly.

- [ ] **Step 3: Wire the guard**

Modify `src/cli/commands/install.ts`:

```ts
import { assertModeOffAllowed } from '../ci-bypass-guard.js';
```

Then call it before the direct off-mode delegation:

```ts
      if (process.env.NPM_GATE_MODE === 'off' && !options.dryRun && !options.noExecute) {
        assertModeOffAllowed(process.env);
        process.exitCode = await runPackageManager(
          packageManager,
          [command, ...allArgs],
          process.cwd()
        );
        return;
      }
```

- [ ] **Step 4: Run command tests to verify pass**

Run:

```sh
pnpm test tests/unit/install-command.test.ts tests/unit/ci-bypass-guard.test.ts
```

Expected: pass.

### Task 3: Fix CI Example And Docs

- [ ] **Step 1: Update GitHub Actions example**

Modify `examples/ci-gate/github-actions.yml` so dependency installation cannot run lifecycle scripts before the gate:

```yaml
name: Dependency Gate

on:
  pull_request:

jobs:
  npm-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: pnpm install --ignore-scripts --frozen-lockfile
      - run: pnpm build
      - run: node dist/index.js ci --release-audit --json
        env:
          NPM_GATE_MODE: ci
```

- [ ] **Step 2: Update CI docs**

Modify `docs/ci-usage.md` to state that script-enabled install before the gate is unsafe and that `NPM_GATE_MODE=off` is rejected in CI/release contexts.

- [ ] **Step 3: Update README**

Modify the CI snippet in `README.md` to match the safe example.

- [ ] **Step 4: Run focused verification**

Run:

```sh
pnpm test tests/unit/install-command.test.ts tests/unit/ci-bypass-guard.test.ts
pnpm typecheck
```

Expected: both commands pass.

- [ ] **Step 5: Commit**

```sh
git add src/cli/ci-bypass-guard.ts src/cli/commands/install.ts tests/unit/ci-bypass-guard.test.ts tests/unit/install-command.test.ts examples/ci-gate/github-actions.yml docs/ci-usage.md README.md
git commit -m "fix: block ci bypass mode and harden bootstrap docs"
```
