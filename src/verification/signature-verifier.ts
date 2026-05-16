export type SignatureVerificationStatus =
  | 'verified'
  | 'missing'
  | 'present-unverified'
  | 'unavailable'
  | 'invalid';

export interface SignatureVerificationResult {
  status: SignatureVerificationStatus;
  signaturesVerified?: boolean;
  provenanceVerified?: boolean;
  message?: string;
}

export interface SignatureVerificationRequest {
  cwd: string;
  packageName: string;
  version: string;
}

export interface SignatureVerifier {
  verify(request: SignatureVerificationRequest): Promise<SignatureVerificationResult>;
}
