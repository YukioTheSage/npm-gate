# Phase 4 Trusted Publishing Provenance Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit trusted-publishing policy checks for high-impact packages without treating provenance or trusted publishing as safety bypasses.

**Architecture:** Extend the existing provenance analyzer with separate trusted-publishing signals. Keep metadata interpretation conservative and configurable. Policy decides severity and blocking through existing signal IDs and strict mode behavior.

**Tech Stack:** TypeScript, Zod config schema, Vitest.

---

## File Structure

- Modify: `src/core/types.ts` - add policy fields and trusted-publishing rule type.
- Modify: `src/config/default-policy.ts` and `src/config/schema.ts` - validate new policy.
- Modify: `src/analyzers/provenance-analyzer.ts` - add trusted-publishing signals.
- Modify: `src/core/engine.ts` - call trusted-publishing analyzer.
- Test: `tests/unit/provenance-analyzer.test.ts` - analyzer coverage.
- Test: `tests/unit/config-loader.test.ts` - production defaults.
- Modify: `docs/policy.md`, `docs/examples.md`, and `README.md` - config examples.

### Task 1: Add Config Shape

- [ ] **Step 1: Write failing config test**

Add to `tests/unit/config-loader.test.ts`:

```ts
test('production profile requires trusted publishing for high impact packages when configured', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-trusted-publishing-'));
  await writeFile(
    join(cwd, 'npm-gate.config.json'),
    JSON.stringify({
      profile: 'production',
      highImpactPackageNames: ['@company/core'],
      requireTrustedPublishingForHighImpactPackages: true
    })
  );

  const loaded = await loadConfig({ cwd, env: { NPM_GATE_MODE: 'ci' } });

  expect(loaded.policy.requireTrustedPublishingForHighImpactPackages).toBe(true);
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/config-loader.test.ts
```

Expected: fail because the config field is unknown.

- [ ] **Step 3: Add types and schema**

In `src/core/types.ts`:

```ts
requireTrustedPublishingForHighImpactPackages: boolean;
trustedPublishing: TrustedPublishingRule[];
```

Add:

```ts
export interface TrustedPublishingRule {
  package: string;
  repository?: string;
  workflow?: string;
  issuer?: string;
}
```

In defaults:

```ts
requireTrustedPublishingForHighImpactPackages: false,
trustedPublishing: [],
```

In production profile defaults:

```ts
requireTrustedPublishingForHighImpactPackages: true,
```

Add matching Zod schema.

- [ ] **Step 4: Run config tests**

Run:

```sh
pnpm test tests/unit/config-loader.test.ts
```

Expected: pass.

### Task 2: Add Trusted Publishing Analyzer

- [ ] **Step 1: Write failing analyzer tests**

Add to `tests/unit/provenance-analyzer.test.ts`:

```ts
import { trustedPublishingSignals } from '../../src/analyzers/provenance-analyzer.js';

test('flags missing trusted publishing for required high impact package', () => {
  const signals = trustedPublishingSignals({
    manifest: { name: '@company/core', version: '1.0.0', dist: {} },
    packageName: '@company/core',
    required: true
  });

  expect(signals).toEqual([
    expect.objectContaining({
      id: 'missing-trusted-publishing',
      severity: 'high'
    })
  ]);
});

test('flags trusted publishing metadata mismatches', () => {
  const signals = trustedPublishingSignals({
    manifest: {
      name: '@company/core',
      version: '1.0.0',
      dist: {
        provenance: {
          repository: 'company/core',
          workflow: '.github/workflows/release.yml'
        }
      }
    },
    packageName: '@company/core',
    required: true,
    expected: {
      package: '@company/core',
      repository: 'company/core',
      workflow: '.github/workflows/publish.yml'
    }
  });

  expect(signals.map((signal) => signal.id)).toContain('trusted-publishing-source-mismatch');
});
```

- [ ] **Step 2: Run analyzer tests to verify failure**

Run:

```sh
pnpm test tests/unit/provenance-analyzer.test.ts
```

Expected: fail because `trustedPublishingSignals` does not exist.

- [ ] **Step 3: Implement analyzer**

Add to `src/analyzers/provenance-analyzer.ts`:

```ts
export function trustedPublishingSignals(input: {
  manifest: PackageManifest;
  packageName: string;
  required: boolean;
  expected?: TrustedPublishingRule;
}): RiskSignal[] {
  const provenance = provenanceObject(input.manifest);
  const hasTrustedSignal = Boolean(provenance.repository || provenance.workflow || provenance.issuer);

  if (input.required && !hasTrustedSignal) {
    return [
      {
        id: 'missing-trusted-publishing',
        score: 55,
        severity: 'high',
        riskCategory: 'provenance_risk',
        message: `Trusted publishing evidence is missing for ${input.packageName}`,
        evidence: [{ type: 'trusted-publishing', message: 'No trusted publishing metadata found' }],
        remediation: ['Use npm trusted publishing or document an approved release exception.'],
        canOverride: true
      }
    ];
  }

  if (!input.expected) return [];
  const mismatches = ['repository', 'workflow', 'issuer'].flatMap((field) => {
    const expected = input.expected?.[field as 'repository' | 'workflow' | 'issuer'];
    if (!expected) return [];
    return provenance[field] === expected ? [] : [{ field, expected, actual: provenance[field] }];
  });

  return mismatches.length === 0
    ? []
    : [
        {
          id: 'trusted-publishing-source-mismatch',
          score: 65,
          severity: 'high',
          riskCategory: 'provenance_risk',
          message: `Trusted publishing metadata did not match policy for ${input.packageName}`,
          evidence: [{ type: 'trusted-publishing', message: 'Trusted publishing mismatch', value: mismatches }],
          remediation: ['Verify the release workflow and trusted publisher configuration.'],
          canOverride: true
        }
      ];
}
```

- [ ] **Step 4: Wire engine**

In `src/core/engine.ts`, compute:

```ts
const expectedTrustedPublishing = loaded.policy.trustedPublishing.find(
  (rule) => rule.package === candidate.name
);
signals.push(
  ...trustedPublishingSignals({
    manifest: current,
    packageName: candidate.name,
    required:
      loaded.policy.requireTrustedPublishingForHighImpactPackages &&
      loaded.policy.highImpactPackageNames.includes(candidate.name),
    expected: expectedTrustedPublishing
  })
);
```

Repeat the same logic for transitive dependency manifests.

- [ ] **Step 5: Run focused tests**

Run:

```sh
pnpm test tests/unit/provenance-analyzer.test.ts tests/unit/config-loader.test.ts tests/unit/policy-engine.test.ts
pnpm typecheck
```

Expected: pass.

- [ ] **Step 6: Commit**

```sh
git add src/core/types.ts src/config/default-policy.ts src/config/schema.ts src/analyzers/provenance-analyzer.ts src/core/engine.ts tests/unit/provenance-analyzer.test.ts tests/unit/config-loader.test.ts docs/policy.md docs/examples.md README.md
git commit -m "feat: add trusted publishing policy signals"
```
