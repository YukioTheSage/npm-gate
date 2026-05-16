import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { loadSignedIncidentFeed } from '../../src/intelligence/signed-feed.js';

describe('signed incident feed', () => {
  test('loads advisories only when signature verifies', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-signed-feed-'));
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const payload = JSON.stringify({
      packages: [
        {
          name: 'compromised-package',
          versions: ['1.2.3'],
          type: 'malicious',
          severity: 'critical',
          summary: 'Confirmed malicious publish'
        }
      ]
    });
    const signature = sign(null, Buffer.from(payload), privateKey).toString('base64');
    const feedPath = join(cwd, 'feed.json');
    await writeFile(feedPath, JSON.stringify({ payload: JSON.parse(payload), signature }));

    const feed = await loadSignedIncidentFeed({
      path: feedPath,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
    });

    expect(feed.packages[0]).toEqual(
      expect.objectContaining({ name: 'compromised-package', type: 'malicious' })
    );
  });

  test('rejects feed payloads when signature verification fails', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-signed-feed-tampered-'));
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const signedPayload = JSON.stringify({ packages: [] });
    const signature = sign(null, Buffer.from(signedPayload), privateKey).toString('base64');
    const feedPath = join(cwd, 'feed.json');
    await writeFile(
      feedPath,
      JSON.stringify({
        payload: {
          packages: [
            {
              name: 'compromised-package',
              versions: ['1.2.3'],
              type: 'malicious',
              severity: 'critical',
              summary: 'Tampered after signing'
            }
          ]
        },
        signature
      })
    );

    await expect(
      loadSignedIncidentFeed({
        path: feedPath,
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
      })
    ).rejects.toThrow(/signature verification failed/i);
  });
});
