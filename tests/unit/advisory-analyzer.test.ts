import { describe, expect, test } from 'vitest';
import {
  loadLocalAdvisoryFeed,
  matchLocalAdvisories,
  parseNpmAuditJson
} from '../../src/analyzers/advisory-analyzer.js';

describe('advisory analyzer', () => {
  test('parses a local malicious advisory feed and matches exact versions', async () => {
    const feed = await loadLocalAdvisoryFeed('tests/fixtures/npm-gate-advisories.json');

    expect(matchLocalAdvisories(feed, 'advisory-malicious-package', '1.2.3')).toEqual([
      {
        name: 'advisory-malicious-package',
        versions: ['1.2.3'],
        type: 'malicious',
        severity: 'critical',
        summary: 'Synthetic test fixture only'
      }
    ]);
  });

  test('parses npm audit JSON vulnerabilities into advisory records', () => {
    const advisories = parseNpmAuditJson(
      JSON.stringify({
        vulnerabilities: {
          lodash: {
            name: 'lodash',
            severity: 'high',
            title: 'Synthetic audit fixture',
            range: '<4.17.21'
          }
        }
      })
    );

    expect(advisories).toEqual([
      {
        name: 'lodash',
        versions: ['<4.17.21'],
        type: 'vulnerability',
        severity: 'high',
        summary: 'Synthetic audit fixture'
      }
    ]);
  });
});
