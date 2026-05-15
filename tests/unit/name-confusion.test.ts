import { describe, expect, test } from 'vitest';
import { detectNameConfusion } from '../../src/analyzers/name-confusion-analyzer.js';

describe('name confusion analyzer', () => {
  test('detects separator and edit-distance similarity to protected names', () => {
    const finding = detectNameConfusion('lodas_h', ['lodash', '@company/pkg']);

    expect(finding).toMatchObject({
      protectedName: 'lodash',
      confidence: 'high'
    });
    expect(finding?.explanation).toContain('similar');
  });

  test('detects scope confusion', () => {
    const finding = detectNameConfusion('company-pkg', ['@company/pkg']);

    expect(finding).toMatchObject({
      protectedName: '@company/pkg',
      confidence: 'high'
    });
  });
});
