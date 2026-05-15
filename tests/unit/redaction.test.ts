import { describe, expect, test } from 'vitest';
import { redactSecrets } from '../../src/utils/exec.js';

describe('token redaction', () => {
  test('redacts npm tokens, auth URL credentials, and token-like environment output', () => {
    const input =
      'https://user:pass@registry.npmjs.org //registry.npmjs.org/:_authToken=npm_secret NPM_TOKEN=npm_secret';

    expect(redactSecrets(input)).toBe(
      'https://[redacted]@registry.npmjs.org //registry.npmjs.org/:_authToken=[redacted] NPM_TOKEN=[redacted]'
    );
  });
});
