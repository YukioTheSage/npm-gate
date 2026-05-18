# Modern npm Supply Chain Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make strict CI and production gates explicitly block high-confidence modern npm supply-chain attack signals.

**Architecture:** Reuse npm-gate's existing analyzers and policy engine. Keep local balanced mode usable, but make strict, CI, production, and emergency contexts convert modern attack indicators from review/warn states into explicit block decisions. Preserve report shape by changing decisions and remediation only through existing fields.

**Tech Stack:** TypeScript, Vitest, Commander, existing npm-gate policy engine and analyzer modules.

---

## File Structure

- Modify: `src/policy/policy-engine.ts` - add conditional hard-block decisions for strict release gates.
- Modify: `tests/unit/policy-engine.test.ts` - test strict blocking for patch dependency additions, binary additions, obfuscation, invisible Unicode, and remote/exotic source signals.
- Modify: `docs/policy.md` - document strict CI/production blocking semantics.
- Modify: `README.md` - make `npm-gate ci --release-audit` the recommended release gate.

## Task 1: Strict Release Gate Blocks Modern Attack Signals

**Files:**
- Modify: `tests/unit/policy-engine.test.ts`
- Modify: `src/policy/policy-engine.ts`

- [ ] **Step 1: Write failing policy-engine tests**

Add this test to `tests/unit/policy-engine.test.ts` near the other strict policy tests:

```ts
  test('strict release gates block modern supply-chain attack indicators explicitly', () => {
    for (const signalId of [
      'new-dependency-in-patch-release',
      'new-binary-file',
      'new-suspicious-file',
      'obfuscated-code-pattern',
      'invisible-unicode-source',
      'unsupported-remote-tarball',
      'remote-tarball-uninspectable',
      'remote-tarball-manifest-missing',
      'remote-tarball-manifest-invalid'
    ]) {
      const balanced = decidePackage({
        candidate: { name: 'fixture', version: '1.0.1' },
        policy: { ...defaultPolicy, policyMode: 'balanced' },
        mode: 'warn',
        policyMode: 'balanced',
        signals: [
          {
            id: signalId,
            score: signalId === 'new-binary-file' ? 60 : 35,
            severity: signalId === 'new-binary-file' ? 'high' : 'medium',
            message: signalId,
            manualReview: signalId.startsWith('new-'),
            canOverride: !signalId.startsWith('remote-tarball') && signalId !== 'unsupported-remote-tarball'
          }
        ]
      });
      expect(['warn', 'manual_review', 'block']).toContain(balanced.decision);

      const strict = decidePackage({
        candidate: { name: 'fixture', version: '1.0.1' },
        policy: { ...defaultPolicy, policyMode: 'strict' },
        mode: 'warn',
        policyMode: 'strict',
        signals: [
          {
            id: signalId,
            score: signalId === 'new-binary-file' ? 60 : 35,
            severity: signalId === 'new-binary-file' ? 'high' : 'medium',
            message: signalId,
            manualReview: signalId.startsWith('new-'),
            canOverride: !signalId.startsWith('remote-tarball') && signalId !== 'unsupported-remote-tarball'
          }
        ]
      });

      expect(strict.decision, signalId).toBe('block');
      expect(strict.killChain, signalId).toContain(`Blocked: fixture@1.0.1 matched ${signalId}`);
    }
  });
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```sh
pnpm test tests/unit/policy-engine.test.ts
```

Expected: FAIL because at least `new-dependency-in-patch-release`, `new-suspicious-file`, `obfuscated-code-pattern`, and `invisible-unicode-source` are not currently explicit hard blocks under `policyMode: "strict"` unless the CLI separately applies strict exit semantics.

- [ ] **Step 3: Implement conditional hard-block sets**

In `src/policy/policy-engine.ts`, add this helper above `mustBlockSignal`:

```ts
function isStrictReleaseGate(
  policy: PolicyConfig,
  mode: RuntimeMode,
  policyMode: PolicyMode
): boolean {
  return (
    mode === 'ci' ||
    policy.profile === 'production' ||
    policyMode === 'strict' ||
    policyMode === 'emergency'
  );
}
```

Then add this near the top of `mustBlockSignal`, after the emergency check and before existing special cases:

```ts
  const strictReleaseBlockSignals = new Set([
    'new-dependency-in-patch-release',
    'new-binary-file',
    'new-suspicious-file',
    'obfuscated-code-pattern',
    'invisible-unicode-source',
    'unsupported-remote-tarball',
    'remote-tarball-uninspectable',
    'remote-tarball-manifest-missing',
    'remote-tarball-manifest-invalid'
  ]);
  if (isStrictReleaseGate(policy, mode, policyMode) && strictReleaseBlockSignals.has(signal.id)) {
    return true;
  }
```

- [ ] **Step 4: Run the focused test and verify it passes**

Run:

```sh
pnpm test tests/unit/policy-engine.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```sh
git add src/policy/policy-engine.ts tests/unit/policy-engine.test.ts
git commit -m "fix: block modern attack signals in strict gates"
```

## Task 2: Document Strict Release-Audit Protection

**Files:**
- Modify: `README.md`
- Modify: `docs/policy.md`

- [ ] **Step 1: Write the documentation change**

In `README.md`, update the CI section so the release recommendation includes this command:

```sh
pnpm install --ignore-scripts --frozen-lockfile
npm-gate ci --release-audit
```

Also add one sentence in the policy summary:

```md
For release and incident-response jobs, use `npm-gate ci --release-audit`; it enables production policy, strict exit behavior, direct tarball inspection, transitive dependency inspection, and deep tarball inspection for transitive packages.
```

In `docs/policy.md`, update the "Production CI Policy" section with:

```md
Strict release gates explicitly block high-confidence modern attack indicators, including patch or minor releases that add dependencies, new binary or shell artifacts, obfuscated tarball code, invisible Unicode source controls, unsupported remote tarballs, required intelligence outages, integrity mismatches, and dangerous workflow trust boundaries. Local balanced mode can still report some of these as warnings or manual review findings, but CI and production should treat them as release blockers.
```

- [ ] **Step 2: Verify docs contain no placeholder language**

Run:

```sh
rg -n "[T]BD|[T]O[D]O|[P]LACEHOLDER|implement[ ]later" README.md docs/policy.md
```

Expected: exit code 1 with no matches.

- [ ] **Step 3: Commit Task 2**

```sh
git add README.md docs/policy.md
git commit -m "docs: recommend strict release audit gate"
```

## Task 3: Final Verification

**Files:**
- Verify only.

- [ ] **Step 1: Run typecheck**

```sh
pnpm typecheck
```

Expected: PASS.

- [ ] **Step 2: Run lint**

```sh
pnpm lint
```

Expected: PASS.

- [ ] **Step 3: Run tests**

```sh
pnpm test
```

Expected: PASS.

- [ ] **Step 4: Run build**

```sh
pnpm build
```

Expected: PASS.

- [ ] **Step 5: Run pack smoke**

```sh
pnpm smoke:pack
```

Expected: PASS.

## Self-Review

- Spec coverage: The plan hardens CI/production decisions, keeps local balanced mode usable, avoids code execution during analysis, preserves JSON shape, and includes tests for policy behavior changes.
- Placeholder scan: No placeholder terms are intentionally present.
- Type consistency: The plan uses existing `PolicyConfig`, `RuntimeMode`, `PolicyMode`, `RiskSignal`, `decidePackage`, and existing signal IDs.
