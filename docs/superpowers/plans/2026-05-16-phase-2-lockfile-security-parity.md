# Phase 2 Lockfile Security Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend unapproved-host and baseline-integrity checks from `package-lock.json` to `pnpm-lock.yaml` and Yarn classic `yarn.lock`.

**Architecture:** Keep project-level lockfile security in `src/analyzers/lockfile-security-analyzer.ts`, but split parser helpers inside the file by lockfile family. Preserve existing signal IDs and add source lockfile evidence.

**Tech Stack:** TypeScript, YAML parser already in dependencies, Vitest.

---

## File Structure

- Modify: `src/analyzers/lockfile-security-analyzer.ts` - add pnpm and yarn parsers.
- Modify: `src/core/types.ts` - add optional baseline paths to `ScanProjectOptions`.
- Modify: `src/core/engine.ts` - pass baseline paths into lockfile analyzer.
- Modify: `src/cli/commands/ci.ts` - add baseline CLI options.
- Test: `tests/unit/lockfile-security-analyzer.test.ts` - parser and signal coverage.
- Test: `tests/unit/ci-command.test.ts` - CLI option forwarding coverage.
- Modify: `docs/ci-usage.md` and `docs/policy.md` - document baseline support.

### Task 1: Add pnpm Host Detection

- [ ] **Step 1: Write failing test**

Add to `tests/unit/lockfile-security-analyzer.test.ts`:

```ts
test('blocks pnpm resolved hosts outside approved registries', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-pnpm-host-'));
  await writeFile(
    join(cwd, 'pnpm-lock.yaml'),
    [
      'lockfileVersion: "9.0"',
      'packages:',
      '  left-pad@1.3.0:',
      '    resolution:',
      '      tarball: https://evil.example/left-pad/-/left-pad-1.3.0.tgz',
      '      integrity: sha512-current'
    ].join('\n')
  );

  const signals = await analyzeLockfileSecurity(cwd, {
    approvedRegistryHosts: ['registry.npmjs.org']
  });

  expect(signals).toEqual([
    expect.objectContaining({
      id: 'unapproved-resolved-host',
      evidence: [
        expect.objectContaining({
          value: expect.objectContaining({
            file: 'pnpm-lock.yaml',
            package: 'left-pad',
            host: 'evil.example'
          })
        })
      ]
    })
  ]);
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/lockfile-security-analyzer.test.ts
```

Expected: fail because pnpm host entries are ignored.

- [ ] **Step 3: Implement pnpm entries**

In `src/analyzers/lockfile-security-analyzer.ts`, import YAML parsing:

```ts
import { parse as parseYaml } from 'yaml';
```

Add a normalized entry type:

```ts
interface LockSecurityEntry {
  file: string;
  key: string;
  name: string;
  version?: string;
  resolved?: string;
  integrity?: string;
}
```

Add pnpm parsing:

```ts
function parsePnpmPackageKey(key: string): { name: string; version: string } | undefined {
  const normalized = key.trim().replace(/^\/+/, '').replace(/\([^)]*\)$/, '');
  const versionAt = normalized.lastIndexOf('@');
  if (versionAt <= 0) return undefined;
  const name = normalized.slice(0, versionAt);
  const version = normalized.slice(versionAt + 1);
  return name && version ? { name, version } : undefined;
}

async function pnpmLockEntries(path: string): Promise<LockSecurityEntry[]> {
  const lock = parseYaml(await readFile(path, 'utf8')) as
    | { packages?: Record<string, { resolution?: { tarball?: string; integrity?: string } }> }
    | null;
  return Object.entries(lock?.packages ?? {}).flatMap(([key, entry]) => {
    const parsed = parsePnpmPackageKey(key);
    if (!parsed) return [];
    return [
      {
        file: 'pnpm-lock.yaml',
        key,
        name: parsed.name,
        version: parsed.version,
        resolved: entry.resolution?.tarball,
        integrity: entry.resolution?.integrity
      }
    ];
  });
}
```

Update `analyzeLockfileSecurity()` to append pnpm entries when `pnpm-lock.yaml` exists.

- [ ] **Step 4: Run test to verify pass**

Run:

```sh
pnpm test tests/unit/lockfile-security-analyzer.test.ts
```

Expected: pass.

### Task 2: Add Yarn Host Detection

- [ ] **Step 1: Write failing test**

Add:

```ts
test('blocks yarn resolved hosts outside approved registries', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-yarn-host-'));
  await writeFile(
    join(cwd, 'yarn.lock'),
    [
      '"left-pad@^1.3.0":',
      '  version "1.3.0"',
      '  resolved "https://evil.example/left-pad/-/left-pad-1.3.0.tgz#abc"',
      '  integrity sha512-current'
    ].join('\n')
  );

  const signals = await analyzeLockfileSecurity(cwd, {
    approvedRegistryHosts: ['registry.npmjs.org']
  });

  expect(signals[0]).toEqual(
    expect.objectContaining({
      id: 'unapproved-resolved-host',
      evidence: [
        expect.objectContaining({
          value: expect.objectContaining({
            file: 'yarn.lock',
            package: 'left-pad',
            host: 'evil.example'
          })
        })
      ]
    })
  );
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/lockfile-security-analyzer.test.ts
```

Expected: fail because Yarn resolved entries are ignored.

- [ ] **Step 3: Implement Yarn entries**

Add parser:

```ts
function yarnNamesFromHeader(header: string): string[] {
  return header.split(/,\s*/).map((part) => {
    const clean = part.trim().replace(/^"|"$/g, '');
    const at = clean.startsWith('@')
      ? clean.indexOf('@', clean.indexOf('/'))
      : clean.lastIndexOf('@');
    return at > 0 ? clean.slice(0, at) : clean;
  });
}

async function yarnLockEntries(path: string): Promise<LockSecurityEntry[]> {
  const entries: LockSecurityEntry[] = [];
  const content = await readFile(path, 'utf8');
  let names: string[] = [];
  let version: string | undefined;
  let resolved: string | undefined;
  let integrity: string | undefined;
  let key = '';

  function flush(): void {
    for (const name of names) {
      entries.push({ file: 'yarn.lock', key, name, version, resolved, integrity });
    }
  }

  for (const line of content.split(/\r?\n/)) {
    const header = line.match(/^("?)([^"\s][^:]+)\1:\s*$/);
    if (header) {
      flush();
      key = header[2]!;
      names = yarnNamesFromHeader(key);
      version = undefined;
      resolved = undefined;
      integrity = undefined;
      continue;
    }
    version = line.match(/^\s+version\s+"([^"]+)"/)?.[1] ?? version;
    resolved = line.match(/^\s+resolved\s+"([^"]+)"/)?.[1] ?? resolved;
    integrity = line.match(/^\s+integrity\s+(.+)$/)?.[1]?.trim() ?? integrity;
  }
  flush();
  return entries.filter((entry) => entry.version || entry.resolved || entry.integrity);
}
```

- [ ] **Step 4: Run test to verify pass**

Run:

```sh
pnpm test tests/unit/lockfile-security-analyzer.test.ts
```

Expected: pass.

### Task 3: Add pnpm And Yarn Integrity Baselines

- [ ] **Step 1: Write failing tests**

Add tests for unchanged package/version with changed integrity in `pnpm-lock.yaml` and `yarn.lock`. Use `previousPnpmLockPath` and `previousYarnLockPath` in options.

```ts
const signals = await analyzeLockfileSecurity(cwd, {
  approvedRegistryHosts: ['registry.npmjs.org'],
  previousPnpmLockPath: previous
});

expect(signals).toEqual([
  expect.objectContaining({
    id: 'lockfile-integrity-changed'
  })
]);
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```sh
pnpm test tests/unit/lockfile-security-analyzer.test.ts
```

Expected: fail because new options do not exist.

- [ ] **Step 3: Add options and comparison**

Extend `LockfileSecurityOptions`:

```ts
export interface LockfileSecurityOptions {
  approvedRegistryHosts: string[];
  previousPackageLockPath?: string;
  previousPnpmLockPath?: string;
  previousYarnLockPath?: string;
}
```

Compare entries by `${file}:${key}` and only emit integrity-change signals when `name`, `version`, and `integrity` are present and the version did not change.

- [ ] **Step 4: Wire CLI and engine options**

Add to `src/core/types.ts`:

```ts
previousPnpmLockPath?: string;
previousYarnLockPath?: string;
```

Add to `src/cli/commands/ci.ts`:

```ts
.option('--previous-pnpm-lock <path>', 'compare pnpm-lock integrity against a baseline')
.option('--previous-yarn-lock <path>', 'compare yarn.lock integrity against a baseline')
```

Pass these through `scanProject()` and `projectPolicySignals()`, including env fallbacks `NPM_GATE_BASE_PNPM_LOCK` and `NPM_GATE_BASE_YARN_LOCK`.

- [ ] **Step 5: Run verification**

Run:

```sh
pnpm test tests/unit/lockfile-security-analyzer.test.ts tests/unit/ci-command.test.ts
pnpm typecheck
```

Expected: pass.

- [ ] **Step 6: Commit**

```sh
git add src/analyzers/lockfile-security-analyzer.ts src/core/types.ts src/core/engine.ts src/cli/commands/ci.ts tests/unit/lockfile-security-analyzer.test.ts tests/unit/ci-command.test.ts docs/ci-usage.md docs/policy.md
git commit -m "feat: extend lockfile security checks to pnpm and yarn"
```
