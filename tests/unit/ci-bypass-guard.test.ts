import { describe, expect, test } from 'vitest';
import { assertModeOffAllowed } from '../../src/cli/ci-bypass-guard.js';

describe('CI bypass guard', () => {
  test('rejects off mode in GitHub Actions', () => {
    expect(() =>
      assertModeOffAllowed({ NPM_GATE_MODE: 'off', GITHUB_ACTIONS: 'true' })
    ).toThrow(/NPM_GATE_MODE=off is forbidden/);
  });

  test('rejects off mode in generic CI', () => {
    expect(() => assertModeOffAllowed({ NPM_GATE_MODE: 'off', CI: 'true' })).toThrow(
      /NPM_GATE_MODE=off is forbidden/
    );
  });

  test('rejects off mode during release jobs', () => {
    expect(() =>
      assertModeOffAllowed({ NPM_GATE_MODE: 'off', NPM_GATE_RELEASE: 'true' })
    ).toThrow(/NPM_GATE_MODE=off is forbidden/);
  });

  test('allows off mode locally', () => {
    expect(() => assertModeOffAllowed({ NPM_GATE_MODE: 'off' })).not.toThrow();
  });
});
