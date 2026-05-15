import { z } from 'zod';
import { defaultPolicy } from './default-policy.js';

export const runtimeModeSchema = z.enum(['off', 'warn', 'block', 'ci']);
export const policyProfileSchema = z.enum(['default', 'production', 'audit-only']);
export const policyModeSchema = z.enum(['balanced', 'strict', 'emergency']);
export const intelligenceSourceSchema = z.enum(['npm-audit', 'osv', 'local']);

export const policySchema = z
  .object({
    profile: policyProfileSchema.default(defaultPolicy.profile),
    policyMode: policyModeSchema.default(defaultPolicy.policyMode),
    minimumReleaseAgeHours: z
      .number()
      .int()
      .nonnegative()
      .default(defaultPolicy.minimumReleaseAgeHours),
    blockLifecycleScripts: z.boolean().default(defaultPolicy.blockLifecycleScripts),
    warnLifecycleScripts: z.boolean().default(defaultPolicy.warnLifecycleScripts),
    blockGitDependencies: z.boolean().default(defaultPolicy.blockGitDependencies),
    warnGitDependencies: z.boolean().default(defaultPolicy.warnGitDependencies),
    requireProvenanceForHighImpactPackages: z
      .boolean()
      .default(defaultPolicy.requireProvenanceForHighImpactPackages),
    warnMissingProvenanceWhenPreviouslyPresent: z
      .boolean()
      .default(defaultPolicy.warnMissingProvenanceWhenPreviouslyPresent),
    warnMissingRegistrySignature: z.boolean().default(defaultPolicy.warnMissingRegistrySignature),
    blockNewPackageNamesInCI: z.boolean().default(defaultPolicy.blockNewPackageNamesInCI),
    blockSuspiciousNameConfusion: z.boolean().default(defaultPolicy.blockSuspiciousNameConfusion),
    blockKnownMaliciousAdvisories: z.boolean().default(defaultPolicy.blockKnownMaliciousAdvisories),
    warnUnknownPackages: z.boolean().default(defaultPolicy.warnUnknownPackages),
    maxRiskScoreAllowed: z
      .number()
      .int()
      .min(0)
      .max(100)
      .default(defaultPolicy.maxRiskScoreAllowed),
    maxRiskScoreWarn: z.number().int().min(0).max(100).default(defaultPolicy.maxRiskScoreWarn),
    allowOverridesWithJustification: z
      .boolean()
      .default(defaultPolicy.allowOverridesWithJustification),
    disallowOverridesInCI: z.boolean().default(defaultPolicy.disallowOverridesInCI),
    protectedPackageNames: z.array(z.string().min(1)).default(defaultPolicy.protectedPackageNames),
    highImpactPackageNames: z
      .array(z.string().min(1))
      .default(defaultPolicy.highImpactPackageNames),
    requiredIntelligenceSources: z
      .array(intelligenceSourceSchema)
      .default(defaultPolicy.requiredIntelligenceSources),
    approvedRegistryHosts: z.array(z.string().min(1)).default(defaultPolicy.approvedRegistryHosts),
    requireTarballInspection: z.boolean().default(defaultPolicy.requireTarballInspection),
    requireIntegrityMatch: z.boolean().default(defaultPolicy.requireIntegrityMatch),
    inspectTransitiveDependencies: z
      .boolean()
      .default(defaultPolicy.inspectTransitiveDependencies),
    maxDependencyClosurePackages: z
      .number()
      .int()
      .positive()
      .default(defaultPolicy.maxDependencyClosurePackages),
    blockCredentialHarvestingPatterns: z
      .boolean()
      .default(defaultPolicy.blockCredentialHarvestingPatterns),
    blockInstallDownloaders: z.boolean().default(defaultPolicy.blockInstallDownloaders),
    requireWorkflowShaPinning: z.boolean().default(defaultPolicy.requireWorkflowShaPinning),
    forbidReleaseCaches: z.boolean().default(defaultPolicy.forbidReleaseCaches),
    emergencyDenylist: z
      .array(
        z.object({
          package: z.string().min(1),
          versions: z.array(z.string().min(1)).default([]),
          reason: z.string().min(1)
        })
      )
      .default(defaultPolicy.emergencyDenylist),
    expectedProvenance: z
      .array(
        z.object({
          package: z.string().min(1),
          repository: z.string().min(1).optional(),
          workflow: z.string().min(1).optional(),
          ref: z.string().min(1).optional(),
          commitSubject: z.string().min(1).optional()
        })
      )
      .default(defaultPolicy.expectedProvenance),
    sourceVerification: z
      .object({
        enabled: z.boolean().default(defaultPolicy.sourceVerification.enabled),
        rules: z
          .array(
            z.object({
              package: z.string().min(1),
              repository: z.string().min(1),
              tagTemplate: z.string().min(1).optional(),
              commit: z.string().min(1).optional(),
              packageJsonPath: z.string().min(1).optional(),
              required: z.boolean().optional()
            })
          )
          .default(defaultPolicy.sourceVerification.rules)
      })
      .default(defaultPolicy.sourceVerification)
  })
  .strict();

export type PolicyConfigInput = z.input<typeof policySchema>;
