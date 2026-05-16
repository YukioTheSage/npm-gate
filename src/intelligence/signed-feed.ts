import { createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import type { AdvisoryInput, SignedIncidentFeedConfig } from '../core/types.js';

const advisorySchema = z.object({
  name: z.string().min(1),
  versions: z.array(z.string().min(1)),
  type: z.enum(['malicious', 'vulnerability']),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  summary: z.string().min(1)
});

const signedFeedSchema = z.object({
  payload: z.object({
    packages: z.array(advisorySchema)
  }),
  signature: z.string().min(1)
});

export async function loadSignedIncidentFeed(
  config: SignedIncidentFeedConfig
): Promise<{ packages: AdvisoryInput[] }> {
  const raw = signedFeedSchema.parse(JSON.parse(await readFile(config.path, 'utf8')) as unknown);
  const payload = JSON.stringify(raw.payload);
  const verified = verify(
    null,
    Buffer.from(payload),
    createPublicKey(config.publicKeyPem),
    Buffer.from(raw.signature, 'base64')
  );
  if (!verified) throw new Error('Signed incident feed signature verification failed');
  return raw.payload;
}
