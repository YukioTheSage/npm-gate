# Phase 5 Cryptographic Signature Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a verifier abstraction for npm registry signatures and provenance attestations, with offline tests and fail-closed policy when verification is required.

**Architecture:** Keep cryptographic verification out of analyzers. Add a `SignatureVerifier` interface and use injected implementations in the engine. The default CLI implementation may shell out to `npm audit signatures` only when explicitly enabled by policy.

**Tech Stack:** TypeScript, child process wrapper, Vitest mocks, npm CLI optional invocation.

---

## File Structure

- Create: `src/verification/signature-verifier.ts` - interface and result types.
- Create: `src/verification/npm-audit-signatures-verifier.ts` - optional default implementation.
- Modify: `src/core/types.ts` - add verifier and policy config.
- Modify: `src/config/default-policy.ts` and `src/config/schema.ts` - add verification settings.
- Modify: `src/analyzers/signature-analyzer.ts` - convert verification results to signals.
- Modify: `src/core/engine.ts` - call verifier when policy requires or enables it.
- Test: `tests/unit/signature-analyzer.test.ts` - result-to-signal coverage.
- Test: `tests/integration/scan-project.test.ts` - injected verifier behavior.
- Modify: `docs/policy.md` and `docs/ci-usage.md` - document verifier mode.

### Task 1: Define Verifier Interface

- [ ] **Step 1: Write failing analyzer test**

Create `tests/unit/signature-analyzer.test.ts`:

```ts
import { describe, expect, test } from 'vitest';
import { signatureVerificationSignals } from '../../src/analyzers/signature-analyzer.js';

describe('signature analyzer', () => {
  test('blocks required unavailable cryptographic verification', () => {
    const signals = signatureVerificationSignals({
      packageName: 'left-pad',
      version: '1.3.0',
      required: true,
      result: { status: 'unavailable', message: 'npm audit signatures not found' }
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'signature-verification-unavailable',
        severity: 'high',
        canOverride: false
      })
    ]);
  });

  test('emits no risk for verified signatures and attestations', () => {
    const signals = signatureVerificationSignals({
      packageName: 'left-pad',
      version: '1.3.0',
      required: true,
      result: { status: 'verified', signaturesVerified: true, provenanceVerified: true }
    });

    expect(signals).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/signature-analyzer.test.ts
```

Expected: fail because verification result support does not exist.

- [ ] **Step 3: Add verifier types**

Create `src/verification/signature-verifier.ts`:

```ts
export type SignatureVerificationStatus =
  | 'verified'
  | 'missing'
  | 'present-unverified'
  | 'unavailable'
  | 'invalid';

export interface SignatureVerificationResult {
  status: SignatureVerificationStatus;
  signaturesVerified?: boolean;
  provenanceVerified?: boolean;
  message?: string;
}

export interface SignatureVerificationRequest {
  cwd: string;
  packageName: string;
  version: string;
}

export interface SignatureVerifier {
  verify(request: SignatureVerificationRequest): Promise<SignatureVerificationResult>;
}
```

- [ ] **Step 4: Add analyzer function**

In `src/analyzers/signature-analyzer.ts`, add:

```ts
export function signatureVerificationSignals(input: {
  packageName: string;
  version: string;
  required: boolean;
  result: SignatureVerificationResult;
}): RiskSignal[] {
  if (input.result.status === 'verified') return [];
  const nonOverrideable = input.required && input.result.status === 'unavailable';
  return [
    {
      id:
        input.result.status === 'unavailable'
          ? 'signature-verification-unavailable'
          : 'signature-verification-failed',
      score: input.required ? 70 : 35,
      severity: input.required ? 'high' : 'medium',
      riskCategory: 'provenance_risk',
      message: `Cryptographic signature verification ${input.result.status} for ${input.packageName}@${input.version}`,
      evidence: [
        {
          type: 'signature-verification',
          message: input.result.message ?? input.result.status,
          value: input.result
        }
      ],
      remediation: ['Verify npm registry signatures and provenance attestations before release.'],
      canOverride: !nonOverrideable
    }
  ];
}
```

- [ ] **Step 5: Run analyzer test**

Run:

```sh
pnpm test tests/unit/signature-analyzer.test.ts
```

Expected: pass.

### Task 2: Wire Injected Verifier Into Engine

- [ ] **Step 1: Write failing integration test**

Add to `tests/integration/scan-project.test.ts` a scan with injected verifier:

```ts
const report = await scanProject({
  cwd,
  env: { NPM_GATE_MODE: 'ci' },
  production: true,
  signatureVerifier: {
    async verify() {
      return { status: 'unavailable', message: 'offline fixture' };
    }
  }
});

expect(report.findings.some((finding) => finding.reasons.includes(
  'Cryptographic signature verification unavailable for left-pad@1.3.0'
))).toBe(true);
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/integration/scan-project.test.ts
```

Expected: fail because `signatureVerifier` is not a scan option.

- [ ] **Step 3: Add policy and options**

In `PolicyConfig`:

```ts
verifyRegistrySignatures: boolean;
requireCryptographicSignatureVerification: boolean;
```

Defaults:

```ts
verifyRegistrySignatures: false,
requireCryptographicSignatureVerification: false,
```

Production profile:

```ts
verifyRegistrySignatures: false,
requireCryptographicSignatureVerification: false,
```

Keep production default off initially to avoid requiring host npm CLI behavior. Release projects opt in explicitly.

In `ScanProjectOptions`:

```ts
signatureVerifier?: SignatureVerifier;
```

- [ ] **Step 4: Wire engine**

When `verifyRegistrySignatures` or `requireCryptographicSignatureVerification` is true, call:

```ts
if (context.signatureVerifier && (loaded.policy.verifyRegistrySignatures || loaded.policy.requireCryptographicSignatureVerification)) {
  const result = await context.signatureVerifier.verify({
    cwd: options.cwd,
    packageName: candidate.name,
    version
  });
  signals.push(
    ...signatureVerificationSignals({
      packageName: candidate.name,
      version,
      required: loaded.policy.requireCryptographicSignatureVerification,
      result
    })
  );
}
```

If verification is required and no verifier exists, add `signature-verification-unavailable`.

- [ ] **Step 5: Add default verifier**

Create `src/verification/npm-audit-signatures-verifier.ts` using the existing exec utility. It should run:

```sh
npm audit signatures --json
```

Parse the JSON conservatively. If parsing fails, return `{ status: 'invalid', message }`. If the command cannot run, return `{ status: 'unavailable', message }`.

- [ ] **Step 6: Run verification**

Run:

```sh
pnpm test tests/unit/signature-analyzer.test.ts tests/integration/scan-project.test.ts
pnpm typecheck
```

Expected: pass.

- [ ] **Step 7: Commit**

```sh
git add src/verification/signature-verifier.ts src/verification/npm-audit-signatures-verifier.ts src/core/types.ts src/config/default-policy.ts src/config/schema.ts src/analyzers/signature-analyzer.ts src/core/engine.ts tests/unit/signature-analyzer.test.ts tests/integration/scan-project.test.ts docs/policy.md docs/ci-usage.md
git commit -m "feat: add cryptographic signature verifier interface"
```
