export const finalizedBurnEvidenceClaimCoverage=Object.freeze([
 {claim:'production_finalized_burn_recursive_checkpoint_artifacts_pinned',producer:'prove:authenticated-finalized-burn',validator:'materialize:finalized-burn-recursive-completion',prerequisitePhase:'produce-checkpoint-evidence-secret',prerequisiteProducer:'package:authenticated-checkpoint-outer-evm-proof'},
 {claim:'production_finalized_burn_recursive_checkpoint_receipt_verified',producer:'prove:authenticated-finalized-burn',validator:'materialize:finalized-burn-recursive-completion',prerequisitePhase:'produce-checkpoint-evidence-secret',prerequisiteProducer:'package:authenticated-checkpoint-outer-evm-proof'},
 {claim:'production_finalized_burn_risc0_evm_receipt_verifier_implemented',producer:'package:authenticated-finalized-burn-evm-proof',validator:'materialize:finalized-burn-recursive-completion'},
]);
