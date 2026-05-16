# Phase 8 Published Dependency Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a release-time exact dependency tree verification path for the `npm-gate` package without running lifecycle scripts unexpectedly.

**Architecture:** Add a script that verifies the publish artifact includes an exact dependency strategy. Prefer `npm-shrinkwrap.json` when the project chooses npm-published exact tree semantics. Keep the script deterministic and avoid package-manager installs with lifecycle scripts.

**Tech Stack:** Node script, package metadata, Vitest or direct Node smoke script, pnpm existing scripts.

---

## File Structure

- Create: `scripts/verify-published-dependency-tree.mjs` - release check.
- Modify: `package.json` - add `release:verify-deps` script.
- Modify: `scripts/smoke-pack.mjs` - call dependency-tree verification after pack.
- Create: `docs/release-hardening.md` - release process and shrinkwrap guidance.
- Modify: `README.md` and `docs/policy.md` - link release hardening.
- Test: `tests/unit/release-hardening.test.ts` - import the script helper and verify both failure and success paths.

### Task 1: Add Release Dependency Verification Script

- [ ] **Step 1: Write failing test**

Create `tests/unit/release-hardening.test.ts`:

```ts
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { verifyPublishedDependencyTree } from '../../scripts/verify-published-dependency-tree.mjs';

describe('published dependency tree verification', () => {
  test('rejects package metadata without shrinkwrap when runtime dependencies exist', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-release-deps-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { commander: '^14.0.3' } })
    );

    await expect(verifyPublishedDependencyTree(cwd)).rejects.toThrow(/npm-shrinkwrap.json/);
  });

  test('accepts exact shrinkwrap for runtime dependencies', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-release-deps-ok-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { commander: '^14.0.3' } })
    );
    await writeFile(
      join(cwd, 'npm-shrinkwrap.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { commander: '^14.0.3' } },
          'node_modules/commander': { version: '14.0.3', integrity: 'sha512-fixture' }
        }
      })
    );

    await expect(verifyPublishedDependencyTree(cwd)).resolves.toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/release-hardening.test.ts
```

Expected: fail because the script does not exist or is not importable.

- [ ] **Step 3: Implement script**

Create `scripts/verify-published-dependency-tree.mjs`:

```js
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

export async function verifyPublishedDependencyTree(cwd = process.cwd()) {
  const manifest = await readJson(join(cwd, 'package.json'));
  const dependencies = Object.keys(manifest.dependencies ?? {});
  if (dependencies.length === 0) return;

  let shrinkwrap;
  try {
    shrinkwrap = await readJson(join(cwd, 'npm-shrinkwrap.json'));
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error('Runtime dependencies require npm-shrinkwrap.json for published exact dependency tree verification');
    }
    throw error;
  }

  const packages = shrinkwrap.packages ?? {};
  for (const dependency of dependencies) {
    const entry = packages[`node_modules/${dependency}`];
    if (!entry?.version || !entry?.integrity) {
      throw new Error(`npm-shrinkwrap.json is missing exact version and integrity for ${dependency}`);
    }
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyPublishedDependencyTree().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
```

- [ ] **Step 4: Run unit test**

Run:

```sh
pnpm test tests/unit/release-hardening.test.ts
```

Expected: pass.

### Task 2: Add Release Script And Docs

- [ ] **Step 1: Modify package scripts**

Add to `package.json`:

```json
"release:verify-deps": "node scripts/verify-published-dependency-tree.mjs"
```

- [ ] **Step 2: Add release docs**

Create `docs/release-hardening.md`:

````md
# Release Hardening

Before publishing npm-gate, verify that runtime dependencies have an exact published dependency tree:

```sh
pnpm run release:verify-deps
```

The preferred strategy is `npm-shrinkwrap.json`, because npm publishes it with the package and uses it to define the install tree for consumers. Generate or refresh it only in a reviewed release workflow with lifecycle scripts disabled.
````

- [ ] **Step 3: Link docs**

Add a short link to `README.md` and `docs/policy.md`.

- [ ] **Step 4: Run verification**

Run:

```sh
pnpm test tests/unit/release-hardening.test.ts
pnpm typecheck
pnpm lint
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add scripts/verify-published-dependency-tree.mjs package.json tests/unit/release-hardening.test.ts docs/release-hardening.md README.md docs/policy.md
git commit -m "chore: verify published dependency tree before release"
```
