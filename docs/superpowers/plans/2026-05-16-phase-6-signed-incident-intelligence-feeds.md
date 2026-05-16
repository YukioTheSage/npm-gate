# Phase 6 Signed Incident Intelligence Feeds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional signed incident intelligence feeds for fast-moving malicious package intelligence while keeping deterministic local feeds as the default.

**Architecture:** Add a signed-feed loader under `src/intelligence/` and adapt verified records into the existing `AdvisoryInput` path. Signature verification is explicit and injectable so tests use local keys and fixtures.

**Tech Stack:** TypeScript, Node crypto, Zod config schema, Vitest.

---

## File Structure

- Create: `src/intelligence/signed-feed.ts` - signed feed schema, verification, and advisory mapping.
- Modify: `src/core/types.ts` - add signed feed config and intelligence source name.
- Modify: `src/config/default-policy.ts` and `src/config/schema.ts` - validate feed config.
- Modify: `src/core/engine.ts` - load signed feed advisories and fail closed when required.
- Test: `tests/unit/signed-feed.test.ts` - signature and schema behavior.
- Test: `tests/integration/intelligence-sources.test.ts` - scan integration.
- Modify: `docs/incident-response.md`, `docs/ci-usage.md`, and `docs/policy.md` - feed usage.

### Task 1: Add Signed Feed Loader

- [ ] **Step 1: Write failing unit test**

Create `tests/unit/signed-feed.test.ts`:

```ts
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { loadSignedIncidentFeed } from '../../src/intelligence/signed-feed.js';

describe('signed incident feed', () => {
  test('loads advisories only when signature verifies', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-signed-feed-'));
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const payload = JSON.stringify({
      packages: [
        {
          name: 'compromised-package',
          versions: ['1.2.3'],
          type: 'malicious',
          severity: 'critical',
          summary: 'Confirmed malicious publish'
        }
      ]
    });
    const signature = sign(null, Buffer.from(payload), privateKey).toString('base64');
    const feedPath = join(cwd, 'feed.json');
    await writeFile(feedPath, JSON.stringify({ payload: JSON.parse(payload), signature }));

    const feed = await loadSignedIncidentFeed({
      path: feedPath,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
    });

    expect(feed.packages[0]).toEqual(
      expect.objectContaining({ name: 'compromised-package', type: 'malicious' })
    );
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run:

```sh
pnpm test tests/unit/signed-feed.test.ts
```

Expected: fail because `signed-feed.ts` does not exist.

- [ ] **Step 3: Implement signed feed loader**

Create `src/intelligence/signed-feed.ts`:

```ts
import { createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import type { AdvisoryInput } from '../core/types.js';

const advisorySchema = z.object({
  name: z.string().min(1),
  versions: z.array(z.string().min(1)),
  type: z.enum(['malicious', 'vulnerability']),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  summary: z.string().min(1)
});

const signedFeedSchema = z.object({
  payload: z.object({
    packages: z.array(advisorySchema)
  }),
  signature: z.string().min(1)
});

export interface SignedIncidentFeedConfig {
  path: string;
  publicKeyPem: string;
}

export async function loadSignedIncidentFeed(
  config: SignedIncidentFeedConfig
): Promise<{ packages: AdvisoryInput[] }> {
  const raw = signedFeedSchema.parse(JSON.parse(await readFile(config.path, 'utf8')));
  const payload = JSON.stringify(raw.payload);
  const ok = verify(
    null,
    Buffer.from(payload),
    createPublicKey(config.publicKeyPem),
    Buffer.from(raw.signature, 'base64')
  );
  if (!ok) throw new Error('Signed incident feed signature verification failed');
  return raw.payload;
}
```

- [ ] **Step 4: Run unit test**

Run:

```sh
pnpm test tests/unit/signed-feed.test.ts
```

Expected: pass.

### Task 2: Integrate Feed Into Engine

- [ ] **Step 1: Write failing integration test**

Add to `tests/integration/intelligence-sources.test.ts`:

```ts
test('signed incident feed advisories block matching packages', async () => {
  const report = await scanProject({
    cwd,
    env: { NPM_GATE_MODE: 'ci' },
    advisories: [],
    signedIncidentFeeds: [
      {
        path: feedPath,
        publicKeyPem
      }
    ]
  });

  expect(report.findings).toEqual([
    expect.objectContaining({
      package: 'compromised-package',
      decision: 'block'
    })
  ]);
});
```

- [ ] **Step 2: Run integration test to verify failure**

Run:

```sh
pnpm test tests/integration/intelligence-sources.test.ts
```

Expected: fail because scan options do not support signed feeds.

- [ ] **Step 3: Add types and config**

Extend `IntelligenceSource`:

```ts
export type IntelligenceSource = 'npm-audit' | 'osv' | 'local' | 'signed-feed';
```

Add to `ScanProjectOptions`:

```ts
signedIncidentFeeds?: SignedIncidentFeedConfig[];
```

Add policy config:

```ts
signedIncidentFeeds: SignedIncidentFeedConfig[];
```

Default:

```ts
signedIncidentFeeds: [],
```

Schema requires `path` and `publicKeyPem`.

- [ ] **Step 4: Load feeds in combined advisories**

Modify `combinedAdvisories()` in `src/core/engine.ts`:

```ts
const configuredFeeds = options.signedIncidentFeeds ?? loaded.policy.signedIncidentFeeds;
const signedFeedAdvisories = [];
for (const feed of configuredFeeds) {
  signedFeedAdvisories.push(...(await loadSignedIncidentFeed(feed)).packages);
}
return [...local.packages, ...signedFeedAdvisories, ...(options.advisories ?? [])];
```

Refactor `combinedAdvisories()` to receive `loaded` so policy feeds are available.

- [ ] **Step 5: Fail closed when required feed is unavailable**

If `requiredIntelligenceSources` includes `signed-feed` and feed loading fails, emit `required-intelligence-unavailable` for `signed-feed`.

- [ ] **Step 6: Run verification**

Run:

```sh
pnpm test tests/unit/signed-feed.test.ts tests/integration/intelligence-sources.test.ts
pnpm typecheck
```

Expected: pass.

- [ ] **Step 7: Commit**

```sh
git add src/intelligence/signed-feed.ts src/core/types.ts src/config/default-policy.ts src/config/schema.ts src/core/engine.ts tests/unit/signed-feed.test.ts tests/integration/intelligence-sources.test.ts docs/incident-response.md docs/ci-usage.md docs/policy.md
git commit -m "feat: add signed incident intelligence feeds"
```
