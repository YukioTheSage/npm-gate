import { describe, expect, test } from 'vitest';
import { analyzeFrontendRuntimeEntries } from '../../src/analyzers/frontend-runtime-analyzer.js';

describe('frontend runtime analyzer', () => {
  test('flags wallet, clipboard, transaction, interception, CDN latest, missing SRI, and obfuscation signals', () => {
    const signals = analyzeFrontendRuntimeEntries([
      {
        path: 'package/dist/browser.js',
        size: 4000,
        sample: [
          'window.ethereum.request({ method: "eth_sendTransaction", params: [tx] });',
          'navigator.clipboard.writeText(attackerAddress);',
          'tx.to = "0x0000000000000000000000000000000000000000";',
          'window.fetch = new Proxy(window.fetch, {});',
          'XMLHttpRequest.prototype.open = function() {};',
          'WebSocket.prototype.send = function() {};',
          '<script src="https://cdn.example/lib@latest/index.js"></script>',
          '<script src="https://cdn.example/unsafe.js"></script>',
          'eval(Buffer.from(payload, "base64").toString())'
        ].join('\n')
      }
    ]);

    expect(signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'frontend-runtime-wallet-access',
        'frontend-runtime-clipboard-mutation',
        'frontend-runtime-transaction-mutation',
        'frontend-runtime-fetch-interception',
        'frontend-runtime-xhr-interception',
        'frontend-runtime-websocket-interception',
        'frontend-runtime-cdn-latest',
        'frontend-runtime-missing-sri',
        'frontend-runtime-obfuscated-payload'
      ])
    );
  });

  test('does not flag benign browser code', () => {
    expect(
      analyzeFrontendRuntimeEntries([
        { path: 'package/index.js', size: 20, sample: 'export const add = (a, b) => a + b;' }
      ])
    ).toEqual([]);
  });
});
