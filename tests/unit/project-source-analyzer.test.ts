import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { describe, expect, test } from 'vitest';
import { analyzeProjectRuntimeSources } from '../../src/analyzers/project-source-analyzer.js';

describe('project source analyzer', () => {
  test('flags CDN latest and external scripts without SRI in project sources', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-project-source-'));
    await mkdir(join(cwd, 'src'), { recursive: true });
    await writeFile(
      join(cwd, 'src', 'index.html'),
      [
        '<script src="https://cdn.example/lottie-player@latest/index.js"></script>',
        '<script src="https://cdn.example/pinned@1.2.3/index.js"></script>',
        '<script src="https://cdn.example/safe@1.2.3/index.js" integrity="sha384-fixture"></script>'
      ].join('\n')
    );

    const signals = await analyzeProjectRuntimeSources(cwd);

    expect(signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'project-cdn-latest',
        'project-external-script-missing-sri'
      ])
    );
    expect(signals.every((signal) => signal.riskCategory === 'frontend_runtime_risk')).toBe(true);
    expect(signals).toHaveLength(2);
  });

  test('ignores generated dependency and build directories', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-project-source-ignore-'));
    await mkdir(join(cwd, 'node_modules', 'fixture'), { recursive: true });
    await mkdir(join(cwd, 'dist'), { recursive: true });
    await writeFile(
      join(cwd, 'node_modules', 'fixture', 'index.html'),
      '<script src="https://cdn.example/lib@latest/index.js"></script>'
    );
    await writeFile(
      join(cwd, 'dist', 'index.html'),
      '<script src="https://cdn.example/lib@latest/index.js"></script>'
    );

    await expect(analyzeProjectRuntimeSources(cwd)).resolves.toEqual([]);
  });
});
