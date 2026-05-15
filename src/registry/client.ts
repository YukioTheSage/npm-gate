import { join } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import registryFetch from 'npm-registry-fetch';
import semver from 'semver';
import type { PackageMetadata, RegistryClient } from '../core/types.js';
import { ensureDir, pathExists } from '../utils/fs.js';
import { redactSecrets } from '../utils/exec.js';
import { logger } from '../utils/logger.js';

export interface NpmRegistryClientOptions {
  cwd: string;
  registryUrl?: string;
  offline?: boolean;
  timeoutMs?: number;
}

export class NpmRegistryClient implements RegistryClient {
  private readonly registryUrl: string;
  private readonly cacheDir: string;
  private readonly timeoutMs: number;

  constructor(private readonly options: NpmRegistryClientOptions) {
    this.registryUrl =
      options.registryUrl ?? process.env.npm_config_registry ?? 'https://registry.npmjs.org';
    this.cacheDir = join(options.cwd, '.npm-gate', 'cache', 'metadata');
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async getPackageMetadata(name: string): Promise<PackageMetadata> {
    const cachePath = this.metadataCachePath(name);
    if (this.options.offline) {
      return JSON.parse(await readFile(cachePath, 'utf8')) as PackageMetadata;
    }

    try {
      logger.debug({ package: name, registry: this.registryUrl }, 'fetching npm metadata');
      const metadata = (await registryFetch.json(encodeURIComponent(name).replace(/^%40/, '@'), {
        registry: this.registryUrl,
        timeout: this.timeoutMs,
        retry: { retries: 2, factor: 2, minTimeout: 250, maxTimeout: 2_000 }
      })) as PackageMetadata;
      await ensureDir(this.cacheDir);
      await writeFile(cachePath, `${JSON.stringify(metadata, null, 2)}\n`, 'utf8');
      return metadata;
    } catch (error) {
      if (await pathExists(cachePath)) {
        logger.warn({ package: name }, 'using cached npm metadata after registry failure');
        return JSON.parse(await readFile(cachePath, 'utf8')) as PackageMetadata;
      }
      const message =
        error instanceof Error ? redactSecrets(error.message) : 'Unknown registry error';
      throw new Error(`Failed to fetch npm registry metadata for ${name}: ${message}`);
    }
  }

  async resolveVersion(name: string, range?: string): Promise<string> {
    const metadata = await this.getPackageMetadata(name);
    if (!range || range === 'latest') {
      const latest = metadata['dist-tags']?.latest;
      if (latest) return latest;
    }
    if (range && metadata.versions[range]) return range;
    const versions = Object.keys(metadata.versions).filter((version) => semver.valid(version));
    const resolved = semver.maxSatisfying(versions, range ?? '*', { includePrerelease: true });
    if (!resolved) throw new Error(`Unable to resolve ${name}@${range ?? 'latest'}`);
    return resolved;
  }

  async fetchTarball(tarballUrl: string): Promise<Buffer> {
    if (!this.isSupportedTarballUrl(tarballUrl)) {
      throw new Error(`Refusing to fetch tarball outside configured npm registry: ${tarballUrl}`);
    }
    const response = await registryFetch(tarballUrl, {
      registry: this.registryUrl,
      timeout: this.timeoutMs,
      retry: { retries: 2, factor: 2, minTimeout: 250, maxTimeout: 2_000 }
    });
    return responseToBuffer(response);
  }

  isSupportedTarballUrl(tarballUrl: string): boolean {
    try {
      const url = new URL(tarballUrl);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
      return (
        normalizedUrl(tarballUrl).startsWith(normalizedRegistryUrl(this.registryUrl)) ||
        normalizedUrl(tarballUrl).startsWith('https://registry.npmjs.org/')
      );
    } catch {
      return false;
    }
  }

  private metadataCachePath(name: string): string {
    return join(this.cacheDir, `${encodeURIComponent(name)}.json`);
  }
}

function normalizedRegistryUrl(registryUrl: string): string {
  const normalized = normalizedUrl(registryUrl);
  return normalized.endsWith('/') ? normalized : `${normalized}/`;
}

function normalizedUrl(rawUrl: string): string {
  return new URL(rawUrl).toString();
}

async function responseToBuffer(response: unknown): Promise<Buffer> {
  if (Buffer.isBuffer(response)) return response;
  if (response instanceof ArrayBuffer) return Buffer.from(response);
  if (ArrayBuffer.isView(response)) {
    return Buffer.from(response.buffer, response.byteOffset, response.byteLength);
  }
  if (typeof response === 'string') return Buffer.from(response);
  if (
    response &&
    typeof response === 'object' &&
    'arrayBuffer' in response &&
    typeof response.arrayBuffer === 'function'
  ) {
    return Buffer.from(await response.arrayBuffer());
  }
  throw new Error('Unsupported registry tarball response type');
}
