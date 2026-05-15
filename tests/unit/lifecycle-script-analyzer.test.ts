import { describe, expect, test } from 'vitest';
import {
  detectLifecycleScripts,
  detectNewLifecycleScripts
} from '../../src/analyzers/lifecycle-script-analyzer.js';

describe('lifecycle script analyzer', () => {
  test('detects install-time lifecycle scripts without executing them', () => {
    const result = detectLifecycleScripts({
      name: 'fixture',
      version: '1.0.0',
      scripts: {
        postinstall: 'node fixture.js',
        test: 'vitest'
      }
    });

    expect(result).toEqual([
      {
        name: 'postinstall',
        command: 'node fixture.js'
      }
    ]);
  });

  test('detects newly introduced lifecycle hooks', () => {
    expect(
      detectNewLifecycleScripts(
        { name: 'fixture', version: '1.0.0' },
        { name: 'fixture', version: '1.0.1', scripts: { preinstall: 'node fixture.js' } }
      )
    ).toEqual([{ name: 'preinstall', command: 'node fixture.js' }]);
  });
});
