import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { loadAllowlist, writeAllowlistEntry } from '../../src/policy/allowlist.js';
import { applyExceptions, loadExceptions } from '../../src/policy/exceptions.js';

describe('allowlist and exceptions', () => {
  test('writes and matches allowlist entries with justifications', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-'));

    await writeAllowlistEntry(cwd, {
      package: 'lodash',
      version: '^4.17.21',
      reason: 'SEC-1 reviewed',
      addedBy: 'test',
      addedAt: '2026-05-14T00:00:00.000Z'
    });

    const allowlist = await loadAllowlist(cwd);
    expect(allowlist.match('lodash', '4.17.21')?.reason).toBe('SEC-1 reviewed');
  });

  test('reports suppressed findings instead of silently ignoring them', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-'));
    await writeFile(
      join(cwd, '.npm-gate-exceptions.json'),
      JSON.stringify({
        exceptions: [
          {
            findingId: 'lifecycle-script:fixture@1.0.0',
            package: 'fixture',
            version: '1.0.0',
            reason: 'Reviewed',
            createdAt: '2026-05-14T00:00:00.000Z'
          }
        ]
      })
    );

    const exceptions = await loadExceptions(cwd);
    const [finding] = applyExceptions(exceptions, [
      {
        id: 'lifecycle-script:fixture@1.0.0',
        package: 'fixture',
        version: '1.0.0',
        decision: 'block',
        severity: 'high',
        score: 80,
        reasons: ['Lifecycle script detected'],
        evidence: [],
        remediation: ['Review'],
        canOverride: true
      }
    ]);

    expect(finding.suppressed).toMatchObject({
      reason: 'Reviewed'
    });
  });
});
