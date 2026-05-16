import { runCommand } from '../utils/exec.js';
import type {
  SignatureVerificationRequest,
  SignatureVerificationResult,
  SignatureVerifier
} from './signature-verifier.js';

function stringValues(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap((item) => stringValues(item));
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, nested]) => [
    key,
    ...stringValues(nested)
  ]);
}

function interpretAuditSignaturesJson(value: unknown): SignatureVerificationResult {
  const text = stringValues(value).join(' ').toLowerCase();
  if (/\b(?:invalid|tampered|mismatch|failed|failure|error)\b/.test(text)) {
    return {
      status: 'invalid',
      signaturesVerified: false,
      provenanceVerified: false,
      message: 'npm audit signatures reported invalid verification evidence'
    };
  }
  if (/\bmissing\b/.test(text)) {
    return {
      status: 'missing',
      signaturesVerified: false,
      provenanceVerified: false,
      message: 'npm audit signatures reported missing verification evidence'
    };
  }
  if (/\b(?:unverified|unsigned)\b/.test(text)) {
    return {
      status: 'present-unverified',
      signaturesVerified: false,
      provenanceVerified: false,
      message: 'npm audit signatures reported unverified evidence'
    };
  }
  return {
    status: 'verified',
    signaturesVerified: true,
    provenanceVerified: true,
    message: 'npm audit signatures completed successfully'
  };
}

function commandUnavailable(stderr: string): boolean {
  return /not found|enoent|unable to safely resolve npm cli|cannot find/i.test(stderr);
}

export class NpmAuditSignaturesVerifier implements SignatureVerifier {
  private readonly results = new Map<string, Promise<SignatureVerificationResult>>();

  async verify(request: SignatureVerificationRequest): Promise<SignatureVerificationResult> {
    const cached = this.results.get(request.cwd);
    if (cached) return cached;
    const result = this.run(request.cwd);
    this.results.set(request.cwd, result);
    return result;
  }

  private async run(cwd: string): Promise<SignatureVerificationResult> {
    try {
      const result = await runCommand('npm', ['audit', 'signatures', '--json'], cwd);
      if (result.exitCode !== 0) {
        const message = result.stderr || result.stdout || `npm audit signatures exited ${result.exitCode}`;
        return commandUnavailable(message)
          ? { status: 'unavailable', message }
          : { status: 'invalid', message };
      }
      if (!result.stdout.trim()) {
        return {
          status: 'verified',
          signaturesVerified: true,
          provenanceVerified: true,
          message: 'npm audit signatures completed successfully'
        };
      }
      try {
        return interpretAuditSignaturesJson(JSON.parse(result.stdout) as unknown);
      } catch (error) {
        return {
          status: 'invalid',
          message: error instanceof Error ? error.message : String(error)
        };
      }
    } catch (error) {
      return {
        status: 'unavailable',
        message: error instanceof Error ? error.message : String(error)
      };
    }
  }
}
