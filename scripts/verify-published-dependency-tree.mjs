import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

export async function verifyPublishedDependencyTree(cwd = process.cwd()) {
  const manifest = await readJson(join(cwd, 'package.json'));
  const dependencies = Object.keys(manifest.dependencies ?? {});
  if (dependencies.length === 0) return;

  let shrinkwrap;
  try {
    shrinkwrap = await readJson(join(cwd, 'npm-shrinkwrap.json'));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error(
        'Runtime dependencies require npm-shrinkwrap.json for published exact dependency tree verification'
      );
    }
    throw error;
  }

  const packages = shrinkwrap.packages ?? {};
  for (const dependency of dependencies) {
    const entry = packages[`node_modules/${dependency}`];
    if (!entry?.version || !entry?.integrity) {
      throw new Error(
        `npm-shrinkwrap.json is missing exact version and integrity for ${dependency}`
      );
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyPublishedDependencyTree().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
