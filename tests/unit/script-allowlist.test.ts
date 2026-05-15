import { describe, expect, test } from 'vitest';
import {
  ScriptAllowlist,
  hashScriptCommand
} from '../../src/policy/script-allowlist.js';

describe('script allowlist', () => {
  const script = { name: 'postinstall', command: 'node build-native.js' };

  test('matches only exact package, version, script command hash, integrity, and justification', () => {
    const allowlist = new ScriptAllowlist([
      {
        package: 'native-fixture',
        version: '1.0.0',
        script: 'postinstall',
        commandSha256: hashScriptCommand(script.command),
        integrity: 'sha512-good',
        justification: 'SEC-10 reviewed native build script'
      }
    ]);

    const result = allowlist.authorize({
      packageName: 'native-fixture',
      version: '1.0.0',
      script,
      integrity: 'sha512-good',
      now: new Date('2026-05-15T00:00:00.000Z')
    });

    expect(result.allowed).toBe(true);
    expect(result.entry?.justification).toContain('SEC-10');
  });

  test('rejects broad or stale entries and explains near misses', () => {
    const allowlist = new ScriptAllowlist([
      {
        package: 'native-fixture',
        version: '*',
        script: 'postinstall',
        commandSha256: hashScriptCommand(script.command),
        justification: 'broad package allow is unsafe'
      },
      {
        package: 'native-fixture',
        version: '1.0.0',
        script: 'postinstall',
        commandSha256: hashScriptCommand('node old.js'),
        integrity: 'sha512-good',
        justification: 'old script',
        expiresAt: '2025-01-01T00:00:00.000Z'
      }
    ]);

    const result = allowlist.authorize({
      packageName: 'native-fixture',
      version: '1.0.1',
      script,
      integrity: 'sha512-changed',
      now: new Date('2026-05-15T00:00:00.000Z')
    });

    expect(result.allowed).toBe(false);
    expect(result.failures.map((failure) => failure.reason)).toEqual(
      expect.arrayContaining([
        'version must be exact',
        'version mismatch',
        'script command hash mismatch',
        'integrity mismatch',
        'entry expired'
      ])
    );
  });

  test('requires a non-empty justification', () => {
    const allowlist = new ScriptAllowlist([
      {
        package: 'native-fixture',
        version: '1.0.0',
        script: 'postinstall',
        commandSha256: hashScriptCommand(script.command),
        justification: ''
      }
    ]);

    const result = allowlist.authorize({
      packageName: 'native-fixture',
      version: '1.0.0',
      script,
      now: new Date('2026-05-15T00:00:00.000Z')
    });

    expect(result.allowed).toBe(false);
    expect(result.failures.map((failure) => failure.reason)).toContain('missing justification');
  });
});
