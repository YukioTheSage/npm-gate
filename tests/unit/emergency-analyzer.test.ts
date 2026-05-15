import { describe, expect, test } from 'vitest';
import {
  createEmergencyChecklist,
  emergencyDenylistSignals
} from '../../src/analyzers/emergency-analyzer.js';

describe('emergency analyzer', () => {
  test('blocks known-bad direct and transitive package versions with dependency paths', () => {
    const signals = emergencyDenylistSignals(
      { name: 'bad-package', version: '1.2.3', source: 'transitive' },
      [
        {
          package: 'bad-package',
          versions: ['1.2.3', '1.2.4'],
          reason: 'Active compromise response'
        }
      ],
      ['app@1.0.0', 'parent@2.0.0', 'bad-package@1.2.3']
    );

    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({
      id: 'emergency-denylist-match',
      riskCategory: 'emergency_denylist_risk',
      dependencyPath: ['app@1.0.0', 'parent@2.0.0', 'bad-package@1.2.3']
    });
  });

  test('generates credential rotation and CI cleanup guidance', () => {
    const checklist = createEmergencyChecklist();

    expect(checklist.credentialRotation).toEqual(
      expect.arrayContaining(['Rotate npm tokens', 'Rotate GitHub tokens'])
    );
    expect(checklist.ciCleanup).toEqual(
      expect.arrayContaining(['Clear package-manager caches', 'Review GitHub Actions workflow changes'])
    );
  });
});
