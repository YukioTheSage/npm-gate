export interface SandboxPlan {
  package: string;
  version?: string;
  mode: 'static-only';
  wouldInspect: string[];
  willExecutePackageCode: false;
  notes: string[];
}

export function createSandboxPlan(packageName: string, version?: string): SandboxPlan {
  return {
    package: packageName,
    version,
    mode: 'static-only',
    wouldInspect: [
      'package.json',
      'tarball filenames',
      'lifecycle scripts',
      'dependency manifest changes'
    ],
    willExecutePackageCode: false,
    notes: [
      'npm-gate does not detonate package code by default.',
      'Future container-based analysis must remain isolated and opt-in.'
    ]
  };
}
