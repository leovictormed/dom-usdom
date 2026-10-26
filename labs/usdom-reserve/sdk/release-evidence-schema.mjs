export const RELEASE_EVIDENCE_KEYS=Object.freeze([
  'checkpointBootstrapRatificationReport','checkpointFinalizedEventReport',
  'checkpointProofCapacityReport','checkpointProvingProgramArtifact',
  'checkpointProvingProgramSourceManifest','checkpointRegistryArtifact',
  'checkpointRegistryReproducibleBuildReport','checkpointTrustedSetup',
  'checkpointVerifierArtifact','checkpointVerifierConfigManifest',
  'checkpointVerifierReproducibleBuildReport','checkpointVerifyingKeyArtifact','controlPlane',
  'controlPlaneEvidenceBundle','controlPlaneRecoveryDrillReport','controlPlaneSeparationReport',
  'safeRecoveryFinalEvidenceBundle',
  'domConsensusAuditReports','mainnetColdStartAttestationReport','mainnetForkRehearsalReport',
  'mainnetPredeploymentAttestationReport','nativePrivacyTrustedSetupAttestationReport',
  'nativeRuntimeManifest','nativeRuntimeSpendVerifyingKeyArtifact',
  'nativeScheduledRuntimeActivationAttestationReport','nativeWalletCustodyAttestationReport',
  'nativeWalletRecoveryAttestationReport','operationsReviewReport','privacyCircuitAuditReports',
  'provingProgramArtifact','provingProgramSourceManifest','realFinalizedEndToEndReport','releaseId',
  'reproducibleBuildReport','reserveArtifact','residualRiskAcceptanceReport','schema',
  'securityValidationReport','solidityAuditReports','sourceCommit','sourceTag','trustedSetup',
  'riscZeroHealthSourceCatalog','verifierArtifact','verifierConfigManifest',
  'verifierReproducibleBuildReport','verifyingKeyArtifact',
]);

export function isExactReleaseEvidenceShape(value) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())
      ===JSON.stringify([...RELEASE_EVIDENCE_KEYS].sort());
}
